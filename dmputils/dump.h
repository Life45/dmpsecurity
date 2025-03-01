#pragma once
#include "parsing.h"

class DriverDumper
{
private:
	Parser& parser;
public:
	DriverDumper(Parser& parser) : parser(parser) {}
	bool Dump(const std::string& driverName);
};
