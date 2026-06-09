#pragma once

#include "nt_defs.h"
#include "intrinsics.h"
#include "hash.h"
#include "peb.h"

namespace syscall::pe {

    constexpr unsigned int kMaxForwardDepth = 5;

    SYSCALL_FORCEINLINE nt::IMAGE_EXPORT_DIRECTORY* get_export_dir(nt::PVOID module_base) {
        auto* base = static_cast<nt::BYTE*>(module_base);

        auto* dos = reinterpret_cast<nt::IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != nt::kImageDosSig)
            return nullptr;

        auto* nt_hdrs = reinterpret_cast<nt::IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        if (nt_hdrs->Signature != nt::kImageNtSig)
            return nullptr;

        nt::DWORD export_rva = nt_hdrs->OptionalHeader.DataDirectory[0].VirtualAddress;
        if (!export_rva)
            return nullptr;

        return reinterpret_cast<nt::IMAGE_EXPORT_DIRECTORY*>(base + export_rva);
    }

    SYSCALL_FORCEINLINE unsigned int hash_forward_module(const char* name, unsigned int len) {
        unsigned int h = hash::fnv1a_basis;
        for (unsigned int i = 0; i < len; ++i) {
            unsigned char c = static_cast<unsigned char>(name[i]);
            if (c >= 'A' && c <= 'Z')
                c += 32;

            h ^= c;
            h *= hash::fnv1a_prime;
            h *= hash::fnv1a_prime;
        }
        const char* suffix = ".dll";
        for (int i = 0; i < 4; ++i) {
            h ^= static_cast<unsigned char>(suffix[i]);
            h *= hash::fnv1a_prime;
            h *= hash::fnv1a_prime;
        }
        return h;
    }

    SYSCALL_FORCEINLINE nt::PVOID find_export_impl(nt::PVOID module_base, unsigned int func_hash, unsigned int depth) {
        if (depth >= kMaxForwardDepth)
            return nullptr;

        auto* base = static_cast<nt::BYTE*>(module_base);

        auto* dos = reinterpret_cast<nt::IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != nt::kImageDosSig)
            return nullptr;

        auto* nt_hdr = reinterpret_cast<nt::IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        if (nt_hdr->Signature != nt::kImageNtSig)
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

                if (func_rva >= export_dir_rva && func_rva < export_dir_rva + export_dir_size) {
                    auto* fwd = reinterpret_cast<const char*>(base + func_rva);

                    const char* dot = fwd;
                    while (*dot && *dot != '.')
                        ++dot;
                    if (!*dot)
                        return nullptr;

                    unsigned int mod_len = static_cast<unsigned int>(dot - fwd);
                    const char* func_name = dot + 1;

                    // skip ordinal forwards
                    if (*func_name == '#')
                        return nullptr;

                    unsigned int mod_hash = hash_forward_module(fwd, mod_len);
                    unsigned int fwd_func_hash = hash::fnv1a_rt(func_name);

                    nt::PVOID target_base = peb::find_module(mod_hash);
                    if (!target_base)
                        return nullptr;

                    return find_export_impl(target_base, fwd_func_hash, depth + 1);
                }

                return static_cast<nt::PVOID>(base + func_rva);
            }
        }

        return nullptr;
    }

    SYSCALL_FORCEINLINE nt::PVOID find_export(nt::PVOID module_base, unsigned int func_hash) {
        return find_export_impl(module_base, func_hash, 0);
    }

} // namespace syscall::pe
