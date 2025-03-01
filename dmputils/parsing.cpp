#include "parsing.h"
#include "utils.hpp"

bool Parser::ParseLoadedModules()
{
	// Get PsLoadedModuleList
	PLIST_ENTRY PsLoadedModuleList = GetMappedMemoryForVA<PLIST_ENTRY>(GetDumpHeader().PsLoadedModuleList);

	if (!PsLoadedModuleList)
		return false;

	// Iterate through the list
	for (PLIST_ENTRY entry = PsLoadedModuleList->Flink; entry != PsLoadedModuleList; entry = entry->Flink)
	{
		auto module = GetMappedMemoryForVA<PKLDR_DATA_TABLE_ENTRY>((uint64_t)entry);

		if ((PLIST_ENTRY)module == PsLoadedModuleList || entry == nullptr)
			break;

		// Fix the unicode strings so they map to valid buffers
		UNICODE_STRING baseDllName = *(PUNICODE_STRING)&module->BaseDllName;
		UNICODE_STRING fullDllName = *(PUNICODE_STRING)&module->FullDllName;
		baseDllName.Buffer = GetMappedMemoryForVA<PWCHAR>((uint64_t)baseDllName.Buffer);
		fullDllName.Buffer = GetMappedMemoryForVA<PWCHAR>((uint64_t)fullDllName.Buffer);

		LoadedModule loadedModule;

		if (baseDllName.Buffer)
			unicodeToString(baseDllName, loadedModule.name);
		if (fullDllName.Buffer)
			unicodeToString(fullDllName, loadedModule.path);

		loadedModule.base = (void*)module->DllBase;
		loadedModule.size = module->SizeOfImage;

		// Add the module to the list
		loadedModules.push_back(loadedModule);

		entry = (PLIST_ENTRY)(module);
	}

	return true;
}

LoadedModule* Parser::GetModuleByAddress(uint64_t address)
{
	for (auto& module : loadedModules)
	{
		if (address >= (uint64_t)module.base && address < (uint64_t)module.base + module.size)
			return &module;
	}

	return nullptr;
}

LoadedModule* Parser::GetModuleByName(const std::string& name)
{
	for (auto& module : loadedModules)
	{
		if (module.name == name)
			return &module;
	}

	return nullptr;
}
