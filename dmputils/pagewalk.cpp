#include "pagewalk.h"

bool PageWalker::pageCallback(void* address, void* mappedAddress, size_t size)
{
	// Skip if the address is in a module
	if (parser.GetModuleByAddress((uint64_t)address) != nullptr)
		return false;
	
	// Check if we can read MZ at the start of the page
	if (*(USHORT*)mappedAddress == IMAGE_DOS_SIGNATURE)
	{
		std::cout << "Encountered MZ at page start, addr: " << std::hex << (uint64_t)address << std::endl;
	}

	return true;
}

bool PageWalker::execPageCallback(void* address, void* mappedAddress, size_t size)
{
	// Skip if the address is in a module
	if (parser.GetModuleByAddress((uint64_t)address) != nullptr)
		return false;

	std::cout << "Exec page(not inside module): " << std::hex << (uint64_t)address << std::endl;

	return true;
}

bool PageWalker::Walk()
{
	// Get the mapped page of DTB
	pml4e_64* dtbAddr = (pml4e_64*)(parser.GetPhysicalPage(parser.GetDirectoryTableBase()));

	if (dtbAddr == 0)
	{
		std::cout << "Failed to get the DTB." << std::endl;
		return false;
	}

	// Iterate through the PML4 table
	for (auto pml4idx = 0; pml4idx < 512; pml4idx++)
	{
		// Get the PML4 entry
		auto pml4e = dtbAddr[pml4idx];

		// Skip non present entries
		if (!pml4e.present)
			continue;

		// Get the PDPT table
		pdpte_64* pdptAddr = (pdpte_64*)(parser.GetPhysicalPage(pml4e.page_frame_number << 12));

		if (pdptAddr == 0)
			continue;

		// Iterate through the PDPT table
		for (auto pdptidx = 0; pdptidx < 512; pdptidx++)
		{
			// Get the PDPT entry
			auto pdpte = pdptAddr[pdptidx];

			if (!pdpte.present)
				continue;

			// Skip 1GB pages because of laziness
			if (pdpte.large_page)
				continue;

			// Get the PD table
			pde_64* pdeAddr = (pde_64*)(parser.GetPhysicalPage(pdpte.page_frame_number << 12));

			if (pdeAddr == 0)
				continue;

			// Iterate through the PDE table
			for (auto pdeidx = 0; pdeidx < 512; pdeidx++)
			{
				// Get the PD entry
				auto pde = pdeAddr[pdeidx];

				if (!pde.present)
					continue;

				// Handle 2mb pages
				if (pde.large_page)
				{
					pde_2mb_64 pde2mb = *(pde_2mb_64*)&pde;

					// Get the physical address of the 2mb page
					void* physicalAddress = (void*)parser.GetPhysicalPage(pde2mb.page_frame_number << 21);

					if (physicalAddress == 0)
						continue;

					// Get the virtual address of the 2mb page
					pml4_virtual_address vaddr = { 0 };
					vaddr.pml4_idx = pml4idx;
					vaddr.pdpt_idx = pdptidx;
					vaddr.pd_idx = pdeidx;

					signExtend(vaddr);

					void* virtualAddress = (void*)(vaddr.address);

					pageCallback(virtualAddress, physicalAddress, 2 * 0x1000 * 0x1000);

					if (!pde2mb.execute_disable)
						execPageCallback(virtualAddress, physicalAddress, 0x1000);

					continue;
				}

				// Get the PT table
				pte_64* pteAddr = (pte_64*)(parser.GetPhysicalPage(pde.page_frame_number << 12));

				if (pteAddr == 0)
					continue;

				// Iterate through the PT table
				for (auto pteidx = 0; pteidx < 512; pteidx++)
				{
					// Get the PT entry
					auto pte = pteAddr[pteidx];

					if (!pte.present)
						continue;

					// Get the physical address of the page
					void* mappedAddress = (void*)parser.GetPhysicalPage(pte.page_frame_number << 12);

					if (mappedAddress == 0)
						continue;

					// Get the virtual address of the page
					pml4_virtual_address vaddr = { 0 };
					vaddr.pml4_idx = pml4idx;
					vaddr.pdpt_idx = pdptidx;
					vaddr.pd_idx = pdeidx;
					vaddr.pt_idx = pteidx;

					signExtend(vaddr);

					void* virtualAddress = (void*)(vaddr.address);

					pageCallback(virtualAddress, mappedAddress, 0x1000);

					// If executable page, call the exec page callback
					if (!pte.execute_disable)
						execPageCallback(virtualAddress, mappedAddress, 0x1000);
				}
			}
		}
	}

	return true;
}