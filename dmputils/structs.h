#pragma once
#include "includes.h"
#include <phnt_windows.h>
#include <phnt.h>

union pml4_virtual_address {
	void const* address;
	struct {
		uint64_t offset : 12;
		uint64_t pt_idx : 9;
		uint64_t pd_idx : 9;
		uint64_t pdpt_idx : 9;
		uint64_t pml4_idx : 9;
		uint64_t sign_bits : 16;
	};
};

struct LoadedModule
{
    std::string name;
    std::string path;
    void* base;
	size_t size;

    LoadedModule()
    {
		base = nullptr;
		size = 0;

        name = "<NameUnknownModule>";
		path = "<PathUnknownModule>";
    }
};

//0xa0 bytes (sizeof), Windows 11 24H2
typedef struct _KLDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    VOID* ExceptionTable;                                                   //0x10
    ULONG ExceptionTableSize;                                               //0x18
    VOID* GpValue;                                                          //0x20
    struct _NON_PAGED_DEBUG_INFO* NonPagedDebugInfo;                        //0x28
    VOID* DllBase;                                                          //0x30
    VOID* EntryPoint;                                                       //0x38
    ULONG SizeOfImage;                                                      //0x40
    struct _UNICODE_STRING FullDllName;                                     //0x48
    struct _UNICODE_STRING BaseDllName;                                     //0x58
    ULONG Flags;                                                            //0x68
    USHORT LoadCount;                                                       //0x6c
    union
    {
        USHORT SignatureLevel:4;                                            //0x6e
        USHORT SignatureType:3;                                             //0x6e
        USHORT Frozen:2;                                                    //0x6e
        USHORT HotPatch:1;                                                  //0x6e
        USHORT Unused:6;                                                    //0x6e
        USHORT EntireField;                                                 //0x6e
    } u1;                                                                   //0x6e
    VOID* SectionPointer;                                                   //0x70
    ULONG CheckSum;                                                         //0x78
    ULONG CoverageSectionSize;                                              //0x7c
    VOID* CoverageSection;                                                  //0x80
    VOID* LoadedImports;                                                    //0x88
    union
    {
        VOID* Spare;                                                        //0x90
        struct _KLDR_DATA_TABLE_ENTRY* NtDataTableEntry;                    //0x90
    };
    ULONG SizeOfImageNotRounded;                                            //0x98
    ULONG TimeDateStamp;                                                    //0x9c
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY; 