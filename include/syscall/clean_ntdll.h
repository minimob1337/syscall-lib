#pragma once

#include "nt_defs.h"
#include "hash.h"
#include "peb.h"
#include "pe.h"

namespace syscall::clean {

    using fn_GetSystemDirectoryW = nt::DWORD(SYSCALL_CALLCONV*)(wchar_t*, nt::DWORD);
    using fn_CreateFileW = nt::HANDLE(SYSCALL_CALLCONV*)(
        const wchar_t*, nt::DWORD, nt::DWORD, nt::PVOID, nt::DWORD, nt::DWORD, nt::HANDLE);
    using fn_CreateFileMappingW = nt::HANDLE(SYSCALL_CALLCONV*)(
        nt::HANDLE, nt::PVOID, nt::DWORD, nt::DWORD, nt::DWORD, const wchar_t*);
    using fn_MapViewOfFile = nt::PVOID(SYSCALL_CALLCONV*)(
        nt::HANDLE, nt::DWORD, nt::DWORD, nt::DWORD, nt::SIZE_T);
    using fn_CloseHandle = int(SYSCALL_CALLCONV*)(nt::HANDLE);
    using fn_UnmapViewOfFile = int(SYSCALL_CALLCONV*)(const void*);

    struct Mapping {
        nt::PVOID base;
        fn_UnmapViewOfFile unmap;
    };

    SYSCALL_FORCEINLINE bool map(Mapping& out) {
        auto* kernel32 = peb::find_module(HASH_CT(L"kernel32.dll"));
        if (!kernel32)
            return false;

        auto get_system_directory = reinterpret_cast<fn_GetSystemDirectoryW>(
            pe::find_export(kernel32, HASH_CT("GetSystemDirectoryW")));
        auto create_file = reinterpret_cast<fn_CreateFileW>(
            pe::find_export(kernel32, HASH_CT("CreateFileW")));
        auto create_mapping = reinterpret_cast<fn_CreateFileMappingW>(
            pe::find_export(kernel32, HASH_CT("CreateFileMappingW")));
        auto map_view = reinterpret_cast<fn_MapViewOfFile>(
            pe::find_export(kernel32, HASH_CT("MapViewOfFile")));
        auto close_handle = reinterpret_cast<fn_CloseHandle>(
            pe::find_export(kernel32, HASH_CT("CloseHandle")));
        auto unmap_view = reinterpret_cast<fn_UnmapViewOfFile>(
            pe::find_export(kernel32, HASH_CT("UnmapViewOfFile")));
        if (!get_system_directory || !create_file || !create_mapping ||
            !map_view || !close_handle || !unmap_view)
            return false;

        wchar_t path[260];
        nt::DWORD length = get_system_directory(path, 260);
        constexpr wchar_t suffix[] = L"\\ntdll.dll";
        constexpr unsigned int suffix_length = sizeof(suffix) / sizeof(suffix[0]);
        if (!length || length >= 260 || length + suffix_length > 260)
            return false;
        for (unsigned int i = 0; i < suffix_length; ++i)
            path[length + i] = suffix[i];

        constexpr nt::DWORD kGenericRead = 0x80000000;
        constexpr nt::DWORD kGenericExecute = 0x20000000;
        constexpr nt::DWORD kShareReadWriteDelete = 0x00000007;
        constexpr nt::DWORD kOpenExisting = 3;
        constexpr nt::DWORD kFileAttributeNormal = 0x80;
        constexpr nt::DWORD kSecImage = 0x01000000;
        constexpr nt::DWORD kFileMapRead = 0x0004;
        constexpr nt::DWORD kFileMapExecute = 0x0020;

        nt::HANDLE file = create_file(path, kGenericRead | kGenericExecute,
            kShareReadWriteDelete, nullptr, kOpenExisting, kFileAttributeNormal, nullptr);
        if (file == reinterpret_cast<nt::HANDLE>(static_cast<long long>(-1)))
            return false;

        nt::HANDLE section = create_mapping(file, nullptr,
            nt::kPageExecRead | kSecImage, 0, 0, nullptr);
        close_handle(file);
        if (!section)
            return false;

        nt::PVOID base = map_view(section, kFileMapRead | kFileMapExecute, 0, 0, 0);
        close_handle(section);
        if (!base)
            return false;

        out.base = base;
        out.unmap = unmap_view;
        return true;
    }

    SYSCALL_FORCEINLINE void unmap(Mapping& mapping) {
        if (mapping.base && mapping.unmap)
            mapping.unmap(mapping.base);
        mapping.base = nullptr;
        mapping.unmap = nullptr;
    }

}
