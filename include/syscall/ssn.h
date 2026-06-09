#pragma once

#include "nt_defs.h"
#include "intrinsics.h"
#include "hash.h"
#include "pe.h"

namespace syscall::ssn {

    struct ZwEntry {
        const char* name;
        unsigned int nt_hash;
        nt::DWORD func_rva;
    };

    struct SsnEntry {
        unsigned int hash;
        unsigned short ssn;
        unsigned short stub_offset;
    };

    constexpr unsigned int kMaxSyscalls = 1024;
    constexpr unsigned int kCacheSize = 1024;
    constexpr unsigned short kMaxSsn = 2048;
    static_assert((kCacheSize & (kCacheSize - 1)) == 0, "cache size must be power of 2");

    // hash Zw name as if it started with "Nt" instead
    SYSCALL_FORCEINLINE unsigned int hash_zw_as_nt(const char* zw_name) {
        unsigned int h = hash::fnv1a_basis;
        h ^= static_cast<unsigned char>('N');
        h *= hash::fnv1a_prime;
        h ^= static_cast<unsigned char>('t');
        h *= hash::fnv1a_prime;
        const char* p = zw_name + 2;
        while (*p) {
            h ^= static_cast<unsigned char>(*p);
            h *= hash::fnv1a_prime;
            ++p;
        }
        return h;
    }

    SYSCALL_FORCEINLINE unsigned int resolve_all(nt::PVOID ntdll_base, SsnEntry* cache, unsigned int cache_capacity, unsigned int xor_key) {
        auto* base = static_cast<nt::BYTE*>(ntdll_base);

        auto* exports = pe::get_export_dir(ntdll_base);
        if (!exports)
            return 0;

        auto* names = reinterpret_cast<nt::DWORD*>(base + exports->AddressOfNames);
        auto* ordinals = reinterpret_cast<nt::WORD*>(base + exports->AddressOfNameOrdinals);
        auto* functions = reinterpret_cast<nt::DWORD*>(base + exports->AddressOfFunctions);

        ZwEntry zw_entries[kMaxSyscalls];
        unsigned int count = 0;

        for (nt::DWORD i = 0; i < exports->NumberOfNames && count < kMaxSyscalls; ++i) {
            auto* name = reinterpret_cast<const char*>(base + names[i]);
            if (name[0] == 'Z' && name[1] == 'w') {
                zw_entries[count].name = name;
                zw_entries[count].nt_hash = hash_zw_as_nt(name);
                zw_entries[count].func_rva = functions[ordinals[i]];
                ++count;
            }
        }

        // sort by address, ntdll lays out stubs in SSN order
        for (unsigned int i = 1; i < count; ++i) {
            ZwEntry tmp = zw_entries[i];
            unsigned int j = i;
            while (j > 0 && zw_entries[j - 1].func_rva > tmp.func_rva) {
                zw_entries[j] = zw_entries[j - 1];
                --j;
            }
            zw_entries[j] = tmp;
        }

        // index after sorting = SSN
        for (unsigned int i = 0; i < count; ++i) {
            if (i >= kMaxSsn)
                break;

            unsigned int nt_hash = zw_entries[i].nt_hash;
            unsigned int slot = nt_hash & (cache_capacity - 1);
            unsigned int probes = 0;

            while (cache[slot].hash != 0 && probes < cache_capacity) {
                slot = (slot + 1) & (cache_capacity - 1);
                ++probes;
            }
            if (probes >= cache_capacity)
                continue;

            cache[slot].hash = nt_hash ^ xor_key;
            cache[slot].ssn = static_cast<unsigned short>(i) ^ static_cast<unsigned short>(xor_key);
            cache[slot].stub_offset = 0;
        }

        intrinsics::secure_zero(zw_entries, sizeof(zw_entries));

        return count;
    }

    SYSCALL_FORCEINLINE SsnEntry* lookup(SsnEntry* cache, unsigned int cache_capacity, unsigned int nt_hash, unsigned int xor_key) {
        unsigned int slot = nt_hash & (cache_capacity - 1);
        unsigned int probes = 0;

        while (cache[slot].hash != 0 && probes < cache_capacity) {
            if (cache[slot].hash == (nt_hash ^ xor_key))
                return &cache[slot];
            slot = (slot + 1) & (cache_capacity - 1);
            ++probes;
        }

        return nullptr;
    }

    SYSCALL_FORCEINLINE unsigned short decrypt_ssn(const SsnEntry* entry, unsigned int xor_key) {
        return entry->ssn ^ static_cast<unsigned short>(xor_key);
    }

    SYSCALL_FORCEINLINE unsigned short decrypt_offset(const SsnEntry* entry, unsigned int xor_key) {
        return entry->stub_offset ^ static_cast<unsigned short>(xor_key >> 16);
    }

} // namespace syscall::ssn
