#pragma once
#include "includes.h"
#include "utils.hpp"

class Parser : public kdmpparser::KernelDumpParser
{
private:
	std::vector<LoadedModule> loadedModules;
public:
	template <typename T>
	T GetMappedMemoryForVA(uint64_t address);

	bool ParseLoadedModules();

    LoadedModule* GetModuleByAddress(uint64_t address);

	LoadedModule* GetModuleByName(const std::string& name);
};

template<typename T>
inline T Parser::GetMappedMemoryForVA(uint64_t address)
{
	// Save the page offset of address
	uint64_t offset = PAGE_OFFSET(address);

	// Get the page for the address
	const uint8_t* page = GetVirtualPage(address);

	if (page == nullptr)
		return (T)0;

	// Add the offset to the page
	return (T)((uint64_t)page + offset);
}