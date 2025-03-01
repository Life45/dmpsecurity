#include "dump.h"
#include <fstream>
#include <iostream>

// todo fix
bool DriverDumper::Dump(const std::string& driverName)
{
	auto module = parser.GetModuleByName(driverName);

	if (module == nullptr)
	{
		std::cout << "Failed to find the module in PsLoadedModuleList." << std::endl;
		return false;
	}
		
	std::string dumpFileName = "dump_" + driverName + ".bin";

	std::ofstream dumpFile(dumpFileName, std::ios::binary);

	if (!dumpFile.is_open())
	{
		std::cout << "Failed to open the dump file." << std::endl;
		return false;
	}

	// Dump the module page by page
	for (size_t i = 0; i < module->size; i += 0x1000)
	{
		auto mappedPage = parser.GetVirtualPage((uint64_t)module->base + i);

		if (mappedPage == nullptr)
			return false;
		
		dumpFile.write((char*)mappedPage, 0x1000);
	}

	dumpFile.close();

	std::cout << "Dumped the driver to " << dumpFileName << std::endl;

	return true;
}
