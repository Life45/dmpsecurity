/*
 * Dynamic Value Relocation Table Parser
 *
 * MIT License
 *
 * Copyright (c) 2025 Berke Akcay
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#pragma once

#include <phnt_windows.h>
#include <phnt.h>
#include <vector>
#include <string>
#include <map>
#include <memory>
#include <iostream>
#include <fstream>

namespace dvrtparser {

    // Forward declarations
    class DVRTEntry;

    // Relocation entry structure to store parsed data
    struct RelocationEntry {
        uint32_t rva;           // Relative(module base) Virtual Address
        bool indirectCall;      // Whether it's an indirect call
        uint8_t registerNumber; // For switch table branches
        uint32_t iatIndex;      // For import control transfers
        bool rexWPrefix;        // For indirect control transfers
        bool cfgCheck;          // For indirect control transfers

        RelocationEntry() : rva(0), indirectCall(false), registerNumber(0),
            iatIndex(0), rexWPrefix(false), cfgCheck(false) {}
    };

    // DVRT entry class to represent a single dynamic relocation
    class DVRTEntry {
    public:
        uint64_t symbol;
        std::vector<RelocationEntry> relocations;

        DVRTEntry(uint64_t symbol) : symbol(symbol) {}
    };

    // Main parser class
    class DVRTParser {
    private:
        std::vector<BYTE> peData;
        std::vector<std::shared_ptr<DVRTEntry>> entries;
        bool isParsed;

        bool parseFunctionOverride(uint64_t& ptr, uint64_t symbol, int& idx, std::shared_ptr<DVRTEntry> entry, size_t dvrtEntrySize)
        {
            RelocationEntry reloc;
            PIMAGE_FUNCTION_OVERRIDE_HEADER functionOverrideHeader = (PIMAGE_FUNCTION_OVERRIDE_HEADER)(ptr);
            auto overrideSize = functionOverrideHeader->FuncOverrideSize;

            for (int i = 0; i < overrideSize;) {
                PIMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION functionOverride =
                    (PIMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION)(ptr + sizeof(IMAGE_FUNCTION_OVERRIDE_HEADER) + i * sizeof(IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION));

                for (int j = 0; j < (functionOverride->RvaSize / sizeof(DWORD)); j++) {
                    PDWORD rva = (PDWORD)((uint64_t)functionOverride + sizeof(IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION) + j * sizeof(DWORD));

                    reloc.rva = *rva;
                    entry->relocations.push_back(reloc);

                    idx++;
                }

                DWORD baseRelocsSize = functionOverride->BaseRelocSize;
                for (int j = 0; j < baseRelocsSize;) {
                    PIMAGE_BASE_RELOCATION baseReloc = (PIMAGE_BASE_RELOCATION)((uint64_t)functionOverride + sizeof(IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION) + functionOverride->RvaSize + j);

                    for (int k = 0; k < (baseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION); k++) {
                        PIMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION rvaInfo = (PIMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION)((uint64_t)baseReloc + sizeof(IMAGE_BASE_RELOCATION) + k * sizeof(IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION));

                        if (rvaInfo->PageRelativeOffset == 0) {
                            continue;
                        }

                        reloc.rva = rvaInfo->PageRelativeOffset + baseReloc->VirtualAddress;
                        entry->relocations.push_back(reloc);

                        idx++;
                    }

                    j += baseReloc->SizeOfBlock;
                }

                i += sizeof(IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION) + functionOverride->RvaSize + baseRelocsSize;
            }

            // calculate bdd size to skip
            size_t bddSize = dvrtEntrySize - overrideSize - sizeof(IMAGE_FUNCTION_OVERRIDE_HEADER);

            ptr += overrideSize + bddSize;
            return true;
        }

        bool parseBaseReloc(uint64_t& ptr, uint64_t symbol, int& idx, std::shared_ptr<DVRTEntry> entry, size_t dvrtEntrySize) {
            if (symbol == IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE) {
                return parseFunctionOverride(ptr, symbol, idx, entry, dvrtEntrySize);
            }

            auto currentPtr = ptr;
            PIMAGE_BASE_RELOCATION baseReloc = (PIMAGE_BASE_RELOCATION)currentPtr;
            currentPtr += sizeof(IMAGE_BASE_RELOCATION);

            while (currentPtr < ptr + baseReloc->SizeOfBlock) {
                RelocationEntry reloc;

                switch (symbol) {
                case IMAGE_DYNAMIC_RELOCATION_GUARD_RF_PROLOGUE:
                {
                    PIMAGE_PROLOGUE_DYNAMIC_RELOCATION_HEADER prologueHeader = (PIMAGE_PROLOGUE_DYNAMIC_RELOCATION_HEADER)(currentPtr);
                    currentPtr += prologueHeader->PrologueByteCount + sizeof(IMAGE_PROLOGUE_DYNAMIC_RELOCATION_HEADER);
                    break;
                }
                case IMAGE_DYNAMIC_RELOCATION_GUARD_RF_EPILOGUE:
                {
                    PIMAGE_EPILOGUE_DYNAMIC_RELOCATION_HEADER epilogueHeader = (PIMAGE_EPILOGUE_DYNAMIC_RELOCATION_HEADER)(currentPtr);
                    currentPtr += epilogueHeader->EpilogueByteCount + sizeof(IMAGE_EPILOGUE_DYNAMIC_RELOCATION_HEADER);
                    currentPtr += epilogueHeader->BranchDescriptorCount * epilogueHeader->BranchDescriptorElementSize;
                    break;
                }
                case IMAGE_DYNAMIC_RELOCATION_GUARD_IMPORT_CONTROL_TRANSFER:
                {
                    PIMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION importControlTransferHeader =
                        (PIMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION)(currentPtr);

                    if (importControlTransferHeader->PageRelativeOffset) {
                        reloc.rva = importControlTransferHeader->PageRelativeOffset + baseReloc->VirtualAddress;
                        reloc.indirectCall = importControlTransferHeader->IndirectCall;
                        reloc.iatIndex = importControlTransferHeader->IATIndex;
                        entry->relocations.push_back(reloc);
                    }
                    else {
                        idx--;
                    }

                    currentPtr += sizeof(IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION);
                    break;
                }
                case IMAGE_DYNAMIC_RELOCATION_GUARD_INDIR_CONTROL_TRANSFER:
                {
                    PIMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION indirControlTransferHeader =
                        (PIMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION)(currentPtr);

                    if (indirControlTransferHeader->PageRelativeOffset) {
                        reloc.rva = indirControlTransferHeader->PageRelativeOffset + baseReloc->VirtualAddress;
                        reloc.indirectCall = indirControlTransferHeader->IndirectCall;
                        reloc.rexWPrefix = indirControlTransferHeader->RexWPrefix;
                        reloc.cfgCheck = indirControlTransferHeader->CfgCheck;
                        entry->relocations.push_back(reloc);
                    }
                    else {
                        idx--;
                    }

                    currentPtr += sizeof(IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION);
                    break;
                }
                case IMAGE_DYNAMIC_RELOCATION_GUARD_SWITCHTABLE_BRANCH:
                {
                    PIMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION switchTableBranchHeader =
                        (PIMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION)(currentPtr);

                    if (switchTableBranchHeader->PageRelativeOffset) {
                        reloc.rva = switchTableBranchHeader->PageRelativeOffset + baseReloc->VirtualAddress;
                        reloc.registerNumber = switchTableBranchHeader->RegisterNumber;
                        entry->relocations.push_back(reloc);
                    }
                    else {
                        idx--;
                    }

                    currentPtr += sizeof(IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION);
                    break;
                }
                case IMAGE_DYNAMIC_RELOCATION_ARM64_KERNEL_IMPORT_CALL_TRANSFER:
                    // Not implemented
                    break;
                default:
                    PIMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION switchTableBranchHeader =
                        (PIMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION)(currentPtr);

                    if (switchTableBranchHeader->PageRelativeOffset) {
                        reloc.rva = switchTableBranchHeader->PageRelativeOffset + baseReloc->VirtualAddress;
                        reloc.registerNumber = switchTableBranchHeader->RegisterNumber;
                        entry->relocations.push_back(reloc);
                    }
                    else {
                        idx--;
                    }

                    currentPtr += sizeof(IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION);
                    break;
                }

                idx++;
            }

            ptr += baseReloc->SizeOfBlock;
            return true;
        }

    public:
        DVRTParser() : isParsed(false) {
        }

        ~DVRTParser() {
        }

        bool loadFile(const std::string& filePath) {
            std::ifstream file(filePath, std::ios::binary);
            if (!file.is_open()) {
                return false;
            }

            file.seekg(0, std::ios::end);
            peData.resize(file.tellg());
            file.seekg(0, std::ios::beg);
            file.read((char*)peData.data(), peData.size());
            file.close();

            isParsed = false;
            entries.clear();

            return true;
        }

        bool loadData(const std::vector<BYTE>& data) {
            peData = data;
            isParsed = false;
            entries.clear();

            return true;
        }

        bool parse() {
            if (peData.empty()) {
                return false;
            }

            // Parse the DOS header
            PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)peData.data();
            if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
                return false;
            }

            // Parse the NT headers
            PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)(peData.data() + dos_header->e_lfanew);
            if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
                return false;
            }

            // Get the data directory for the Dynamic Value Relocation Table
            PIMAGE_DATA_DIRECTORY loadConfigDir = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
            if (loadConfigDir->VirtualAddress == 0 || loadConfigDir->Size == 0) {
                return false;
            }

            PIMAGE_LOAD_CONFIG_DIRECTORY64 loadConfig = (PIMAGE_LOAD_CONFIG_DIRECTORY64)(peData.data() + loadConfigDir->VirtualAddress);

            // Iterate sections to find .reloc
            PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);
            PIMAGE_SECTION_HEADER relocSection = nullptr;

            // Iterate through all sections to find the .reloc section
            for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
                // Check by name for .reloc section
                if (memcmp(section[i].Name, ".reloc", 6) == 0) {
                    relocSection = &section[i];
                    break;
                }
            }

            if (relocSection == nullptr) {
                return false;
            }

            // Get the DVRT header
            PIMAGE_DYNAMIC_RELOCATION_TABLE dvrt_header = (PIMAGE_DYNAMIC_RELOCATION_TABLE)(
                peData.data() + relocSection->PointerToRawData + loadConfig->DynamicValueRelocTableOffset);

            if (dvrt_header->Version != 1) {
                return false;
            }

            entries.clear();

            for (size_t currOffset = 0; currOffset < dvrt_header->Size;) {
                PIMAGE_DYNAMIC_RELOCATION64 dynReloc = (PIMAGE_DYNAMIC_RELOCATION64)(
                    (uint64_t)dvrt_header + sizeof(IMAGE_DYNAMIC_RELOCATION_TABLE) + currOffset);

                auto entry = std::make_shared<DVRTEntry>(dynReloc->Symbol);
                entries.push_back(entry);

                uint64_t currentPtr = (uint64_t)dynReloc + sizeof(IMAGE_DYNAMIC_RELOCATION64);
                int idx = 0;

                while (currentPtr < (uint64_t)dynReloc + sizeof(IMAGE_DYNAMIC_RELOCATION64) + dynReloc->BaseRelocSize) {
                    parseBaseReloc(currentPtr, dynReloc->Symbol, idx, entry, dynReloc->BaseRelocSize);
                }

                currOffset += sizeof(IMAGE_DYNAMIC_RELOCATION64) + dynReloc->BaseRelocSize;
            }

            isParsed = true;
            return true;
        }

        const std::vector<std::shared_ptr<DVRTEntry>>& getEntries() const {
            return entries;
        }

        std::map<uint64_t, std::vector<RelocationEntry>> getEntriesAsMap() const {
            std::map<uint64_t, std::vector<RelocationEntry>> result;

            for (const auto& entry : entries) {
                result[entry->symbol] = entry->relocations;
            }

            return result;
        }

        std::vector<RelocationEntry> getAllRelocations() const {
            std::vector<RelocationEntry> result;

            for (const auto& entry : entries) {
                result.insert(result.end(), entry->relocations.begin(), entry->relocations.end());
            }

            return result;
        }

        void printInfo() const {
            if (!isParsed) {
                std::cout << "DVRT not parsed yet" << std::endl;
                return;
            }

            for (const auto& entry : entries) {
                std::cout << "Symbol: " << entry->symbol << std::endl;

                int idx = 0;
                for (const auto& reloc : entry->relocations) {
                    std::cout << "[" << std::hex << idx << "] :";
                    std::cout << " RVA: " << std::hex << reloc.rva;

                    switch (entry->symbol) {
                    case IMAGE_DYNAMIC_RELOCATION_GUARD_IMPORT_CONTROL_TRANSFER:
                        std::cout << " Indirect: " << std::hex << reloc.indirectCall;
                        std::cout << " IAT Index: " << std::hex << reloc.iatIndex;
                        break;

                    case IMAGE_DYNAMIC_RELOCATION_GUARD_INDIR_CONTROL_TRANSFER:
                        std::cout << " Indirect: " << std::hex << reloc.indirectCall;
                        std::cout << " RexWPrefix: " << std::hex << reloc.rexWPrefix;
                        std::cout << " CfgCheck: " << std::hex << reloc.cfgCheck;
                        break;

                    case IMAGE_DYNAMIC_RELOCATION_GUARD_SWITCHTABLE_BRANCH:
                    default:
                        std::cout << " Register Number: " << std::hex << (int)reloc.registerNumber;
                        break;
                    }

                    std::cout << std::endl;
                    idx++;
                }
            }
        }
    };

} // namespace dvrtparser 