#include "includes.h"
#include "parsing.h"
#include "utils.hpp"
#include "pagewalk.h"
#include "dump.h"
#include "integrity.h"
#include "livedump.h"

void printHelp()
{
    std::cout << "Usage: dmputils <command> [options]" << std::endl;
	std::cout << "Commands:" << std::endl;
	std::cout << "  -ld <folder_path> - Create a live kernel dump(Win11 22621.1928+) at the specified folder, requires admin privilege" << std::endl;
	std::cout << "  -p <dump_path> - Pagewalk all kernel pages" << std::endl;
	std::cout << "  -d <dump_path> <driver> - Extract a driver from the dump and save it." << std::endl;
	std::cout << "  -i <dump_path> <driver> <disk_path> - Perform a disk versus memory integrity check on the driver." << std::endl;
}

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        printHelp();
        return 1;
    }

    std::string command = argv[1];

    if (command == "-ld")
	{
		if (argc != 3)
		{
			printHelp();
			return 1;
		}

		std::string dumpFolder = argv[2];
		bool result = doLiveDump(dumpFolder);
		if (!result)
		{
			std::cout << "Failed to create live dump" << std::endl;
			return 1;
		}
		return 0;
	}
	else if (command == "-p")
	{
		if (argc != 3)
		{
			printHelp();
			return 1;
		}

		std::string dumpPath = argv[2];

		Parser parser;

		bool result = parser.Parse(dumpPath.c_str());
		if (!result)
		{
			std::cout << "Failed to parse dump" << std::endl;
			return 1;
		}

		result = parser.ParseLoadedModules();

		if (!result)
		{
			std::cout << "Failed to parse loaded modules" << std::endl;
			return 1;
		}

		PageWalker walker(parser);
		result = walker.Walk();
		if (!result)
		{
			std::cout << "Failed to pagewalk" << std::endl;
			return 1;
		}
		return 0;
	}
	else if (command == "-d")
	{
		if (argc != 4)
		{
			printHelp();
			return 1;
		}

		std::string dumpPath = argv[2];
		std::string driverName = argv[3];

		Parser parser;
		bool result = parser.Parse(dumpPath.c_str());
		if (!result)
		{
			std::cout << "Failed to parse dump" << std::endl;
			return 1;
		}

		result = parser.ParseLoadedModules();

		if (!result)
		{
			std::cout << "Failed to parse loaded modules" << std::endl;
			return 1;
		}
		
		DriverDumper dumper(parser);
		result = dumper.Dump(driverName);
		if (!result)
		{
			std::cout << "Failed to dump driver" << std::endl;
			return 1;
		}
		return 0;
	}
	else if (command == "-i")
	{
		if (argc != 5)
		{
			printHelp();
			return 1;
		}

		std::string dumpPath = argv[2];
		std::string driverName = argv[3];
		std::string diskPath = argv[4];

		Parser parser;
		bool result = parser.Parse(dumpPath.c_str());
		if (!result)
		{
			std::cout << "Failed to parse dump" << std::endl;
			return 1;
		}

		result = parser.ParseLoadedModules();

		if (!result)
		{
			std::cout << "Failed to parse loaded modules" << std::endl;
			return 1;
		}

		IntegrityChecker checker(parser);
		result = checker.Check(driverName, diskPath);
		if (!result)
		{
			std::cout << "Integrity check failed" << std::endl;
			return 1;
		}	
		return 0;
	}

	return 1;
}
