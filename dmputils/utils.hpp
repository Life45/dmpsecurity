#pragma once
#include "includes.h"

#define PAGE_OFFSET(address) ((address) & 0xfff)

static void signExtend(pml4_virtual_address& vaddr)
{
	// If bit 47 is set (highest used bit in 48-bit address), 
	// then bits 48-63 must all be set to 1
	if ((uint64_t)vaddr.address & (1ULL << 47)) {
		vaddr.sign_bits = 0xFFFF;
	}
	else {
		vaddr.sign_bits = 0;
	}
}

static void unicodeToString(UNICODE_STRING& unicodeString, std::string& string)
{
	if (unicodeString.Buffer == nullptr || unicodeString.Length == 0)
	{
		string.clear();
		return;
	}

	// Convert wide string to narrow string
	int size = WideCharToMultiByte(CP_UTF8, 0, unicodeString.Buffer, 
		unicodeString.Length / sizeof(WCHAR), 
		nullptr, 0, nullptr, nullptr);

	if (size > 0)
	{
		string.resize(size);
		WideCharToMultiByte(CP_UTF8, 0, unicodeString.Buffer,
			unicodeString.Length / sizeof(WCHAR),
			&string[0], size, nullptr, nullptr);
	}
	else
	{
		string.clear();
	}
}
