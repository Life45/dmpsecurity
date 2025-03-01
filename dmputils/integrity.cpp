#include "integrity.h"
#include <fstream>

bool IntegrityChecker::CompareHeaders(const uint8_t* moduleStart, const uint8_t* diskStart, std::vector<Section>& sections)
{
	IMAGE_DOS_HEADER* moduleDosHeader = (IMAGE_DOS_HEADER*)moduleStart;
	IMAGE_DOS_HEADER* diskDosHeader = (IMAGE_DOS_HEADER*)diskStart;

	// Check the DOS header magic
	if ((moduleDosHeader->e_magic != diskDosHeader->e_magic) || diskDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		std::cout << "DOS header magic mismatch or invalid magic." << std::endl;
		return false;
	}

	IMAGE_NT_HEADERS64* moduleNtHeaders = (IMAGE_NT_HEADERS64*)(moduleStart + moduleDosHeader->e_lfanew);
	IMAGE_NT_HEADERS64* diskNtHeaders = (IMAGE_NT_HEADERS64*)(diskStart + diskDosHeader->e_lfanew);

    // Check the NT headers
    if (moduleNtHeaders->Signature != diskNtHeaders->Signature || moduleNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        std::cout << "NT headers signature mismatch or invalid signature." << std::endl;
        return false;
    }

    // Check section headers
    if (moduleNtHeaders->FileHeader.NumberOfSections != diskNtHeaders->FileHeader.NumberOfSections)
    {
        std::cout << "Number of sections mismatch." << std::endl;
        return false;
    } 

    IMAGE_SECTION_HEADER* moduleSection = (IMAGE_SECTION_HEADER*)(moduleNtHeaders + 1);
    IMAGE_SECTION_HEADER* diskSection = (IMAGE_SECTION_HEADER*)(diskNtHeaders + 1);

    // Check each section to ensure characteristics, etc. match
    for (WORD i = 0; i < moduleNtHeaders->FileHeader.NumberOfSections; i++)
    {      
        if (moduleSection->SizeOfRawData != diskSection->SizeOfRawData)
        {
            std::cout << "Section " << i << " size mismatch." << std::endl;
            return false;
        }
        
        if (moduleSection->Characteristics != diskSection->Characteristics)
        {
            std::cout << "Section " << i << " characteristics mismatch." << std::endl;
            return false;
        }
        
        if (moduleSection->Misc.VirtualSize != diskSection->Misc.VirtualSize)
        {
            std::cout << "Section " << i << " virtual size mismatch." << std::endl;
            return false;
        }

        // Add the section to the vector
		sections.push_back({ (char*)moduleSection->Name, moduleSection->VirtualAddress, moduleSection->SizeOfRawData, 
        moduleSection->PointerToRawData, moduleSection->Misc.VirtualSize, moduleSection->Characteristics });

        // Increment the pointers
        moduleSection++;
        diskSection++;
    }
    
    return true;   
}

bool IntegrityChecker::CompareBytes(const uint8_t* moduleStart, const uint8_t* diskStart, size_t size)
{    
    for (size_t i = 0; i < size;)
    {
        ZydisDecodedInstruction moduleInstruction;
        ZydisDecodedOperand moduleOperands[ZYDIS_MAX_OPERAND_COUNT];
        ZyanStatus status = ZydisDecoderDecodeFull(&decoder, moduleStart + i, size - i, &moduleInstruction, moduleOperands);

        if (status != ZYAN_STATUS_SUCCESS)
        {
			i++; // As you could imagine, this is a bad way to handle this. If we blindly increment, decoder might start hallucinating instructions in some random part of the data and break alignment.
            continue;
        }

        // Get the instruction size
        size_t instructionSize = moduleInstruction.length;

        // Skip if same bytes
        if (memcmp(moduleStart + i, diskStart + i, instructionSize) == 0)
        {
			i += instructionSize;
            continue;
        }

		size_t rva = ModuleRVA((uint8_t*)moduleStart + i);

		// Check if the RVA within instruction size should be ignored
		// Q: Why do we need to ignore the RVA ?
		// A: Because of live patches like KASLR, retpoline, import optimizations, etc. Keep in mind that this was done as a workaround, it can be abused pretty easily.
		// Q: Why not just check the RVA instead of the whole instruction ?
		// A: Because the DVRT entry does not always have the exact instruction start address depending on the entry type. 
		//    For example, the entry could have the RVA of the address part in the instruction instead of the start of the instruction.
        if (ShouldIgnoreRva(rva, instructionSize))
        {
            i += instructionSize;
            continue;
        }

        // Now, a mismatch has been found. Disassemble disk part as well.
        ZydisDecodedInstruction diskInstruction;
        ZydisDecodedOperand diskOperands[ZYDIS_MAX_OPERAND_COUNT];
        status = ZydisDecoderDecodeFull(&decoder, diskStart + i, size - i, &diskInstruction, diskOperands);

        if (status != ZYAN_STATUS_SUCCESS)
        {
            std::cout << "Failed to decode disk instruction at offset " << i << std::endl;
            return false;
        }

        // In case the disk instruction is either int3 or nop, it is most likely retpoline or import optimization.
        // We could verify this, but for simplicity, we will just provide broader instruction size so the "ignore filter" can find the specific relocation entry.
        // 
        // Q:Why did we miss this in our earlier should ignore check ?
        // A:Because the DVRT entry most likely has the previous instruction as RVA.
        if (diskInstruction.mnemonic == ZYDIS_MNEMONIC_INT3 || diskInstruction.mnemonic == ZYDIS_MNEMONIC_NOP)
        {
            if (ShouldIgnoreRva(rva - instructionSize * 2, instructionSize * 2)) // lazy ass size
            {
                i += instructionSize;
                continue;
            }
        }

        // Format the instructions
        char moduleInstructionString[1024] = {0};
        char diskInstructionString[1024] = {0};
        status = ZydisFormatterFormatInstruction(&formatter, &moduleInstruction, moduleOperands, 10, moduleInstructionString, sizeof(moduleInstructionString), ZYDIS_RUNTIME_ADDRESS_NONE, ZYAN_NULL);

        if (status != ZYAN_STATUS_SUCCESS)
        {
            std::cout << "Failed to format module instruction at offset " << i << std::endl;
            return false;
        }

        status = ZydisFormatterFormatInstruction(&formatter, &diskInstruction, diskOperands, 10, diskInstructionString, sizeof(diskInstructionString), ZYDIS_RUNTIME_ADDRESS_NONE, ZYAN_NULL);

        if (status != ZYAN_STATUS_SUCCESS)
        {
            std::cout << "Failed to format disk instruction at offset " << i << std::endl;
            return false;
        }

        // Print the instructions
		std::cout << "-- Mismatch at section offset " << std::hex << i << " --" << std::endl;
        std::cout << "Module: " << moduleInstructionString << std::endl;
        std::cout << "Disk: " << diskInstructionString << std::endl;
		std::cout << "--------------------------" << std::endl;

		// Try to continue by skipping the instruction(this can be improved)
		i += instructionSize;
    }
    return true;
}

bool IntegrityChecker::Check(const std::string& driverName, const std::string& diskPath)
{
    // Find the module
    auto module = parser.GetModuleByName(driverName);
    if (module == nullptr)
    {
        std::cout << "Module not found: " << driverName << std::endl;
        return false;
    }

    // Parse DVRT data for disk
	bool result = dvrtParser.loadFile(diskPath);

	if (!result)
	{
		std::cout << "Failed to parse DVRT for disk image." << std::endl;
		return false;
	}

	result = dvrtParser.parse();

    if (!result)
    {
        std::cout << "Failed to parse DVRT for disk image." << std::endl;
        return false;
    }

    relocations = dvrtParser.getAllRelocations();

	std::cout << "Found " << relocations.size() << " entries in DVRT(They will be ignored in the integrity check)." << std::endl;

    // Copy all module pages to a vector
    std::vector<uint8_t> moduleData;
    moduleData.reserve(module->size);

	std::vector<uint64_t> zeroPages;
    
    for (size_t offset = 0; offset < module->size; offset += 0x1000)
    {
        auto mappedPage = parser.GetMappedMemoryForVA<uint8_t*>((uint64_t)module->base + offset);
        if (mappedPage == nullptr)
        {
            std::cout << "Failed to map module page at offset " << std::hex << offset << " , Filling with 0." << std::endl;
			moduleData.insert(moduleData.end(), 0x1000, 0);
			zeroPages.push_back(offset);
            continue;
        }
        
        size_t bytesToCopy = min(0x1000ULL, module->size - offset);
        moduleData.insert(moduleData.end(), mappedPage, mappedPage + bytesToCopy);
    }

    // Read disk image into vector
    std::vector<uint8_t> diskData;
    std::ifstream diskFile(diskPath, std::ios::binary);
    
    if (!diskFile.is_open())
    {
        std::cout << "Failed to open disk file: " << diskPath << std::endl;
        return false;
    }

    diskFile.seekg(0, std::ios::end);
    size_t fileSize = diskFile.tellg();
    diskFile.seekg(0, std::ios::beg);

    diskData.resize(fileSize);
    diskFile.read((char*)diskData.data(), fileSize);
    diskFile.close();

	moduleMappedBase = moduleData.data();
	diskMappedBase = diskData.data();

    // Relocate the disk image
    if (!RelocateDiskImage(diskData, (uint64_t)module->base))
    {
        std::cout << "Failed to relocate disk image." << std::endl;
        return false;
    }

    // Compare the headers
    std::vector<Section> sections;
    if (!CompareHeaders(moduleData.data(), diskData.data(), sections))
    {
        std::cout << "Headers mismatch." << std::endl;
        return false;
    }

    // Iterate each section
    for (size_t i = 0; i < sections.size(); i++)
    {
        auto section = sections[i];

        // Skip non-executable sections
        if (!(section.characteristics & IMAGE_SCN_MEM_EXECUTE))
        {
            continue;
        }

		// Skip discardable sections
        if (section.characteristics & IMAGE_SCN_MEM_DISCARDABLE)
        {
            continue;
        }

        // Skip writable sections(also put a warning because RWX is bad)
        if (section.characteristics & IMAGE_SCN_MEM_WRITE)
        {
            std::cout << "Warning: Section " << section.name << " is writable and executable." << std::endl;
            continue;
        }

        // Get the section from the module
        auto moduleSectionStart = (uint8_t*)moduleData.data() + section.virtualAddress;
        // Get the section from the disk
        auto diskSectionStart = (uint8_t*)diskData.data() + section.pointerToRawData;
        // Get the size of the section
        auto sectionSize = section.sizeOfRawData;

		// Check if any page in this section is zeroed
        bool skip = false;
        for (size_t page = ModuleRVA(moduleSectionStart); page < ModuleRVA(moduleSectionStart) + sectionSize; page += 0x1000)
        {
            if (std::find(zeroPages.begin(), zeroPages.end(), page) != zeroPages.end())
            {
				std::cout << "Warning: Page at RVA " << std::hex << page << " is zeroed. Skipping section " << section.name << std::endl;
				skip = true;
                break;
            }
        }

		if (skip)		
			continue;
        
        // Compare the bytes
        if (!CompareBytes(moduleSectionStart, diskSectionStart, sectionSize))
        {
            std::cout << "Bytes mismatch in section " << section.name << std::endl;
            return false;
        }

		std::cout << "Section " << section.name << " passed." << std::endl;
    }

	std::cout << "Integrity check passed." << std::endl;
    return true;
}

bool IntegrityChecker::RelocateDiskImage(std::vector<uint8_t>& diskImage, uint64_t targetBaseAddress)
{
    // Check if the image is a valid PE file
    if (diskImage.size() < sizeof(IMAGE_DOS_HEADER))
    {
        std::cout << "Invalid PE file: too small for DOS header" << std::endl;
        return false;
    }

    // Get the DOS header
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)diskImage.data();
    
    // Check the DOS signature
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::cout << "Invalid PE file: DOS signature mismatch" << std::endl;
        return false;
    }

    // Ensure the NT headers offset is valid
    if (dosHeader->e_lfanew >= diskImage.size() || 
        dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > diskImage.size())
    {
        std::cout << "Invalid PE file: NT headers out of bounds" << std::endl;
        return false;
    }

    // Get the NT headers
    IMAGE_NT_HEADERS64* ntHeaders = (IMAGE_NT_HEADERS64*)(diskImage.data() + dosHeader->e_lfanew);
    
    // Check the NT signature
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        std::cout << "Invalid PE file: NT signature mismatch" << std::endl;
        return false;
    }

    // Get the preferred base address from the PE header
    uint64_t preferredBaseAddress = ntHeaders->OptionalHeader.ImageBase;
    
    // Calculate the relocation delta
    int64_t relocationDelta = (int64_t)targetBaseAddress - (int64_t)preferredBaseAddress;
    
    std::cout << "Relocating image from 0x" << std::hex << preferredBaseAddress 
              << " to 0x" << targetBaseAddress 
              << " (delta: 0x" << relocationDelta << ")" << std::dec << std::endl;
    
    // If no relocation needed, return success
    if (relocationDelta == 0)
    {
        std::cout << "No relocation needed (image already at correct base)" << std::endl;
        return true;
    }

    // Check if relocation information exists
    IMAGE_DATA_DIRECTORY relocationDir = 
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    
    if (relocationDir.VirtualAddress == 0 || relocationDir.Size == 0)
    {
        std::cout << "Warning: No relocation information found in PE file" << std::endl;
        return false;
    }

    // Build a map of RVA to file offset using section headers
    IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    
    // Function to convert RVA to file offset
    auto rvaToFileOffset = [&](uint32_t rva) -> uint32_t {
        // Find the section containing this RVA
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
        {
            uint32_t sectionRva = sectionHeader[i].VirtualAddress;
            uint32_t sectionSize = sectionHeader[i].Misc.VirtualSize;
            
            if (rva >= sectionRva && rva < sectionRva + sectionSize)
            {
                uint32_t offsetWithinSection = rva - sectionRva;
                return sectionHeader[i].PointerToRawData + offsetWithinSection;
            }
        }
        
        // Not found in any section
        return 0;
    };

    // Convert relocation directory RVA to file offset
    uint32_t relocFileOffset = rvaToFileOffset(relocationDir.VirtualAddress);
    
    if (relocFileOffset == 0 || relocFileOffset >= diskImage.size() || 
        relocFileOffset + relocationDir.Size > diskImage.size())
    {
        std::cout << "Invalid relocation directory file offset" << std::endl;
        return false;
    }

    // Get the relocation table
    uint8_t* relocBase = diskImage.data() + relocFileOffset;
    uint8_t* relocEnd = relocBase + relocationDir.Size;
    
    uint32_t relocationsApplied = 0;
    
    // Process each relocation block
    while (relocBase < relocEnd)
    {
        IMAGE_BASE_RELOCATION* relocBlock = (IMAGE_BASE_RELOCATION*)relocBase;
        
        // Check for valid block size
        if (relocBlock->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION))
        {
            std::cout << "Invalid relocation block size" << std::endl;
            break;
        }
        
        // Get the page RVA (Relative Virtual Address)
        uint32_t pageRVA = relocBlock->VirtualAddress;
        
        // Calculate number of entries in this block
        uint32_t entriesCount = (relocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        
        // Get the entries array
        WORD* entries = (WORD*)(relocBlock + 1);
        
        // Process each entry
        for (uint32_t i = 0; i < entriesCount; i++)
        {
            WORD entry = entries[i];
            uint32_t offset = entry & 0xFFF;  // Lower 12 bits = offset within page
            uint32_t type = entry >> 12;      // Upper 4 bits = relocation type
            
            // Skip padding entries
            if (type == IMAGE_REL_BASED_ABSOLUTE)
                continue;
            
            // Calculate the RVA of this relocation
            uint32_t relocRVA = pageRVA + offset;
            
            // Convert RVA to file offset
            uint32_t fileOffset = rvaToFileOffset(relocRVA);
            
            // Make sure the relocation address is within bounds
            if (fileOffset == 0 || fileOffset >= diskImage.size() || fileOffset + 8 > diskImage.size())
            {
                std::cout << "Relocation address out of bounds: RVA=" << std::hex << relocRVA 
                          << " FileOffset=" << fileOffset << std::endl;
                continue;  // Skip this relocation but continue processing others
            }
            
            // Apply the relocation based on type
            switch (type)
            {
                case IMAGE_REL_BASED_DIR64:  // 64-bit address
                {
                    uint64_t* address = (uint64_t*)(diskImage.data() + fileOffset);
                    *address += relocationDelta;
                    break;
                }
                
                case IMAGE_REL_BASED_HIGHLOW:  // 32-bit address
                {
                    uint32_t* address = (uint32_t*)(diskImage.data() + fileOffset);
                    *address += (uint32_t)relocationDelta;
                    break;
                }
                
                case IMAGE_REL_BASED_HIGH:  // High 16 bits of 32-bit address
                {
                    uint16_t* address = (uint16_t*)(diskImage.data() + fileOffset);
                    *address += HIWORD(relocationDelta);
                    break;
                }
                
                case IMAGE_REL_BASED_LOW:  // Low 16 bits of 32-bit address
                {
                    uint16_t* address = (uint16_t*)(diskImage.data() + fileOffset);
                    *address += LOWORD(relocationDelta);
                    break;
                }
                
                default:
                    // Only log unusual relocation types, but continue processing
                    if (type != IMAGE_REL_BASED_ABSOLUTE && 
                        type != IMAGE_REL_BASED_HIGHLOW && 
                        type != IMAGE_REL_BASED_DIR64)
                    {
                        std::cout << "Unsupported relocation type: " << type << " at RVA " << std::hex << relocRVA << std::endl;
                    }
                    break;
            }
        }
        
        // Move to the next relocation block
        relocBase += relocBlock->SizeOfBlock;
    }

    // Update the ImageBase in the PE header to reflect the new base address
    ntHeaders->OptionalHeader.ImageBase = targetBaseAddress;
    
    return true;
}

bool IntegrityChecker::ShouldIgnoreRva(size_t rva, int within)
{
	// Iterate relocations and check if the RVA is within the instruction size
	for (auto& relocation : relocations)
	{
		if (relocation.rva >= rva && relocation.rva < rva + within)
		{
			return true;
		}
	}

	return false;
}
