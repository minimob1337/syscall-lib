#pragma once

#include "nt_defs.h"
#include "intrinsics.h"
#include "hash.h"

namespace syscall::pe {

    SYSCALL_FORCEINLINE nt::IMAGE_EXPORT_DIRECTORY* get_export_dir(nt::PVOID module_base) {
        auto* base = static_cast<nt::BYTE*>(module_base);

        auto* dos = reinterpret_cast<nt::IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != nt::IMAGE_DOS_SIGNATURE)
            return nullptr;

        auto* nt_hdrs = reinterpret_cast<nt::IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        if (nt_hdrs->Signature != nt::IMAGE_NT_SIGNATURE)
            return nullptr;

        nt::DWORD export_rva = nt_hdrs->OptionalHeader.DataDirectory[0].VirtualAddress;
        if (!export_rva)
            return nullptr;

        return reinterpret_cast<nt::IMAGE_EXPORT_DIRECTORY*>(base + export_rva);
    }

    SYSCALL_FORCEINLINE nt::PVOID find_export(nt::PVOID module_base, unsigned int func_hash) {
        auto* base = static_cast<nt::BYTE*>(module_base);

        auto* dos = reinterpret_cast<nt::IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != nt::IMAGE_DOS_SIGNATURE)
            return nullptr;

        auto* nt_hdr = reinterpret_cast<nt::IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        if (nt_hdr->Signature != nt::IMAGE_NT_SIGNATURE)
            return nullptr;

        nt::DWORD export_dir_rva = nt_hdr->OptionalHeader.DataDirectory[0].VirtualAddress;
        nt::DWORD export_dir_size = nt_hdr->OptionalHeader.DataDirectory[0].Size;
        if (!export_dir_rva)
            return nullptr;

        auto* exports = reinterpret_cast<nt::IMAGE_EXPORT_DIRECTORY*>(base + export_dir_rva);

        auto* names = reinterpret_cast<nt::DWORD*>(base + exports->AddressOfNames);
        auto* ordinals = reinterpret_cast<nt::WORD*>(base + exports->AddressOfNameOrdinals);
        auto* functions = reinterpret_cast<nt::DWORD*>(base + exports->AddressOfFunctions);

        for (nt::DWORD i = 0; i < exports->NumberOfNames; ++i) {
            auto* name = reinterpret_cast<const char*>(base + names[i]);
            if (hash::fnv1a_rt(name) == func_hash) {
                nt::DWORD func_rva = functions[ordinals[i]];

                // skip forwarded exports
                if (func_rva >= export_dir_rva && func_rva < export_dir_rva + export_dir_size)
                    return nullptr;

                return static_cast<nt::PVOID>(base + func_rva);
            }
        }

        return nullptr;
    }

} // namespace syscall::pe
