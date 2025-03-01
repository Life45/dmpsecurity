#pragma once
#include "parsing.h"

class PageWalker
{
private:
    Parser& parser;
    bool pageCallback(void* address, void* mappedAddress, size_t size);
    bool execPageCallback(void* address, void* mappedAddress, size_t size);
public:
	PageWalker(Parser& parser) : parser(parser) {}
	bool Walk();
};
