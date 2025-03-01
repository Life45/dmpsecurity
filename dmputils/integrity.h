#pragma once
#include "parsing.h"
#include <Zydis/Zydis.h>
#include <dvrtparser.h>

struct Section
{
	std::string name;
    uint64_t virtualAddress;
    uint64_t sizeOfRawData;
    uint64_t pointerToRawData;
    uint64_t virtualSize;
	uint64_t characteristics;
};

class IntegrityChecker
{
private:
	Parser& parser;
	ZydisDecoder decoder;
	ZydisFormatter formatter;
	dvrtparser::DVRTParser dvrtParser;
	std::vector<dvrtparser::RelocationEntry> relocations;
	uint8_t* moduleMappedBase = 0;
	uint8_t* diskMappedBase = 0;

	bool CompareHeaders(const uint8_t* moduleStart, const uint8_t* diskStart, std::vector<Section>& sections);
	bool CompareBytes(const uint8_t* moduleStart, const uint8_t* diskStart, size_t size);
	bool RelocateDiskImage(std::vector<uint8_t>& diskImage, uint64_t targetBaseAddress);
	bool ShouldIgnoreRva(size_t rva, int within);

	inline const size_t ModuleRVA(uint8_t* addr)
	{
		return (size_t)(addr - moduleMappedBase);
	}

	inline const size_t DiskRVA(uint8_t* addr)
	{
		return (size_t)(addr - diskMappedBase);
	}
public:
	IntegrityChecker(Parser& parser) : parser(parser) 
	{
		ZyanStatus status = ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
		if (status != ZYAN_STATUS_SUCCESS)
		{
			throw std::runtime_error("Failed to initialize Zydis decoder");
		}

		status = ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
		if (status != ZYAN_STATUS_SUCCESS)
		{
			throw std::runtime_error("Failed to initialize Zydis formatter");
		}
	}
	bool Check(const std::string& driverName, const std::string& diskPath);
};