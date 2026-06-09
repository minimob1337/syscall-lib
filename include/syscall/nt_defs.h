#pragma once

#include "compiler.h"

namespace syscall::nt {

using BYTE = unsigned char;
using USHORT = unsigned short;
using ULONG = unsigned long;
using ULONG_PTR = unsigned long long;
using SIZE_T = unsigned long long;
using LONG = long;
using PVOID = void*;
using HANDLE = void*;
using NTSTATUS = long;
using BOOLEAN = unsigned char;
using DWORD = unsigned long;
using WORD = unsigned short;

struct UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    wchar_t* Buffer;
};

struct LIST_ENTRY {
    LIST_ENTRY* Flink;
    LIST_ENTRY* Blink;
};

struct PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
};

struct LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
};

struct PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    BYTE Padding1[4];
    PVOID Reserved3[2];
    PEB_LDR_DATA* Ldr;
};

struct IMAGE_DOS_HEADER {
    WORD e_magic;
    WORD e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc;
    WORD e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno;
    WORD e_res[4];
    WORD e_oemid, e_oeminfo;
    WORD e_res2[10];
    LONG e_lfanew;
};

struct IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
};

struct IMAGE_FILE_HEADER {
    WORD Machine;
    WORD NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader;
    WORD Characteristics;
};

struct IMAGE_OPTIONAL_HEADER64 {
    WORD Magic;
    BYTE MajorLinkerVersion, MinorLinkerVersion;
    DWORD SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    DWORD AddressOfEntryPoint, BaseOfCode;
    ULONG_PTR ImageBase;
    DWORD SectionAlignment, FileAlignment;
    WORD MajorOperatingSystemVersion, MinorOperatingSystemVersion;
    WORD MajorImageVersion, MinorImageVersion;
    WORD MajorSubsystemVersion, MinorSubsystemVersion;
    DWORD Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
    WORD Subsystem, DllCharacteristics;
    ULONG_PTR SizeOfStackReserve, SizeOfStackCommit;
    ULONG_PTR SizeOfHeapReserve, SizeOfHeapCommit;
    DWORD LoaderFlags, NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

struct IMAGE_EXPORT_DIRECTORY {
    DWORD Characteristics, TimeDateStamp;
    WORD MajorVersion, MinorVersion;
    DWORD Name, Base;
    DWORD NumberOfFunctions, NumberOfNames;
    DWORD AddressOfFunctions;
    DWORD AddressOfNames;
    DWORD AddressOfNameOrdinals;
};

    constexpr DWORD IMAGE_DOS_SIGNATURE = 0x5A4D;
    constexpr DWORD IMAGE_NT_SIGNATURE = 0x00004550;
    constexpr DWORD MEM_COMMIT = 0x00001000;
    constexpr DWORD MEM_RESERVE = 0x00002000;
    constexpr DWORD MEM_RELEASE = 0x00008000;
    constexpr DWORD PAGE_READWRITE = 0x04;
    constexpr DWORD PAGE_EXECUTE_READ = 0x20;
    constexpr DWORD PAGE_EXECUTE_READWRITE = 0x40;
    constexpr ULONG STATUS_SUCCESS = 0x00000000;

using fn_NtAllocateVirtualMemory = NTSTATUS(SYSCALL_CALLCONV*)(
    HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
    SIZE_T* RegionSize, ULONG AllocationType, ULONG Protect);

using fn_NtProtectVirtualMemory = NTSTATUS(SYSCALL_CALLCONV*)(
    HANDLE ProcessHandle, PVOID* BaseAddress, SIZE_T* RegionSize,
    ULONG NewProtect, ULONG* OldProtect);

using fn_NtFreeVirtualMemory = NTSTATUS(SYSCALL_CALLCONV*)(
    HANDLE ProcessHandle, PVOID* BaseAddress, SIZE_T* RegionSize, ULONG FreeType);

} // namespace syscall::nt
