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

    // x64 ntdll stub stride in bytes
    constexpr unsigned int kStubStride = 0x20;
    // max neighbor distance to search in each direction
    constexpr unsigned int kMaxNeighborSearch = 20;

    constexpr unsigned int kMaxNopSkip = 8;

    // check if a syscall stub prologue is hooked
    SYSCALL_FORCEINLINE bool is_stub_hooked(const nt::BYTE* addr) {
        const nt::BYTE* p = addr;

        // skip leading nops
        for (unsigned int n = 0; n < kMaxNopSkip && *p == 0x90; ++n)
            ++p;

        // known hook signatures
        if (p[0] == 0xE9)              return true;  // jmp rel32
        if (p[0] == 0xEB)              return true;  // jmp rel8
        if (p[0] == 0xFF && p[1] == 0x25) return true;  // jmp [rip+disp32]
        if (p[0] == 0xCC)              return true;  // int3
        if (p[0] == 0x0F && p[1] == 0x0B) return true;  // ud2
        if (p[0] == 0xCD && p[1] == 0x03) return true;  // int 3 (alt)
        if (p[0] == 0x68)              return true;  // push imm32

        // intact prologue: 4C 8B D1 B8
        if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8)
            return false;

        // anything else we don't recognize, treat as hooked
        return true;
    }

    // read ssn from an unhooked stub (assumes 4C 8B D1 B8 xx xx 00 00)
    SYSCALL_FORCEINLINE unsigned short read_stub_ssn(const nt::BYTE* addr) {
        const nt::BYTE* p = addr;
        for (unsigned int n = 0; n < kMaxNopSkip && *p == 0x90; ++n)
            ++p;
        // ssn is the two bytes after 4C 8B D1 B8
        return static_cast<unsigned short>(p[4]) |
               (static_cast<unsigned short>(p[5]) << 8);
    }

    // walk neighbors to recover ssn from a hooked stub via halo's gate
    SYSCALL_FORCEINLINE bool recover_ssn_from_neighbors(
        const nt::BYTE* stub_addr,
        const nt::BYTE* image_base,
        nt::DWORD image_size,
        unsigned short& out_ssn)
    {
        for (unsigned int dist = 1; dist <= kMaxNeighborSearch; ++dist) {
            // check neighbor above (with bounds check)
            if (stub_addr - (dist * kStubStride) >= image_base) {
                const nt::BYTE* up = stub_addr - (dist * kStubStride);
                if (!is_stub_hooked(up)) {
                    out_ssn = static_cast<unsigned short>(read_stub_ssn(up) + dist);
                    return true;
                }
            }

            // check neighbor below (with bounds check)
            if (stub_addr + (dist * kStubStride) + kStubStride <= image_base + image_size) {
                const nt::BYTE* down = stub_addr + (dist * kStubStride);
                if (!is_stub_hooked(down)) {
                    out_ssn = static_cast<unsigned short>(read_stub_ssn(down) - dist);
                    return true;
                }
            }
        }
        return false;
    }

    // verify and fix ssns using halo's gate after zw sorting
    SYSCALL_FORCEINLINE unsigned int verify_ssns(nt::PVOID ntdll_base, SsnEntry* cache, unsigned int cache_capacity, unsigned int xor_key) {
        auto* base = static_cast<nt::BYTE*>(ntdll_base);
        auto* exports = pe::get_export_dir(ntdll_base);
        if (!exports)
            return 0;

        auto* names = reinterpret_cast<nt::DWORD*>(base + exports->AddressOfNames);
        auto* ordinals = reinterpret_cast<nt::WORD*>(base + exports->AddressOfNameOrdinals);
        auto* functions = reinterpret_cast<nt::DWORD*>(base + exports->AddressOfFunctions);

        nt::DWORD export_dir_rva = 0;
        nt::DWORD export_dir_size = 0;
        nt::DWORD image_size = 0;
        {
            auto* dos = reinterpret_cast<nt::IMAGE_DOS_HEADER*>(base);
            auto* nt_hdr = reinterpret_cast<nt::IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
            export_dir_rva = nt_hdr->OptionalHeader.DataDirectory[0].VirtualAddress;
            export_dir_size = nt_hdr->OptionalHeader.DataDirectory[0].Size;
            image_size = nt_hdr->OptionalHeader.SizeOfImage;
        }

        unsigned int fixed = 0;

        // walk all exports and match against cache entries by hash
        for (nt::DWORD i = 0; i < exports->NumberOfNames; ++i) {
            auto* name = reinterpret_cast<const char*>(base + names[i]);

            // only check Nt* syscall stubs
            if (name[0] != 'N' || name[1] != 't')
                continue;

            unsigned int nt_hash = hash::fnv1a_rt(name);
            unsigned int slot = nt_hash & (cache_capacity - 1);
            unsigned int probes = 0;
            SsnEntry* entry = nullptr;

            while (cache[slot].hash != 0 && probes < cache_capacity) {
                if (cache[slot].hash == (nt_hash ^ xor_key)) {
                    entry = &cache[slot];
                    break;
                }
                slot = (slot + 1) & (cache_capacity - 1);
                ++probes;
            }

            if (!entry)
                continue;

            // resolve the actual function address
            nt::DWORD func_rva = functions[ordinals[i]];

            // skip forwarded exports
            if (func_rva >= export_dir_rva && func_rva < export_dir_rva + export_dir_size)
                continue;

            auto* stub_addr = base + func_rva;

            if (!is_stub_hooked(stub_addr)) {
                // verify ssn matches
                unsigned short stub_ssn = read_stub_ssn(stub_addr);
                unsigned short cached_ssn = decrypt_ssn(entry, xor_key);
                if (stub_ssn != cached_ssn) {
                    // stub disagrees with zw sorting, trust the stub bytes
                    entry->ssn = stub_ssn ^ static_cast<unsigned short>(xor_key);
                    ++fixed;
                }
            } else {
                // stub is hooked, recover via neighbor walking
                unsigned short recovered_ssn = 0;
                if (recover_ssn_from_neighbors(stub_addr, base, image_size, recovered_ssn)) {
                    unsigned short cached_ssn = decrypt_ssn(entry, xor_key);
                    if (recovered_ssn != cached_ssn) {
                        entry->ssn = recovered_ssn ^ static_cast<unsigned short>(xor_key);
                        ++fixed;
                    }
                }
            }
        }

        return fixed;
    }

} // namespace syscall::ssn
