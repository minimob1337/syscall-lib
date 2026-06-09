#pragma once

#include "nt_defs.h"
#include "hash.h"
#include "peb.h"
#include "pe.h"

namespace syscall::imports {

    struct ImportEntry {
        unsigned int key;
        nt::PVOID addr;
    };

    constexpr unsigned int kImportCacheSize = 256;
    static_assert((kImportCacheSize & (kImportCacheSize - 1)) == 0, "import cache size must be power of 2");

    SYSCALL_FORCEINLINE unsigned int make_key(unsigned int module_hash, unsigned int func_hash) {
        return module_hash ^ (func_hash * hash::fnv1a_prime);
    }

    SYSCALL_FORCEINLINE nt::PVOID resolve(ImportEntry* cache, unsigned int cache_capacity, unsigned int module_hash, unsigned int func_hash) {
        unsigned int key = make_key(module_hash, func_hash);
        unsigned int slot = key & (cache_capacity - 1);
        unsigned int probes = 0;

        while (cache[slot].key != 0 && probes < cache_capacity) {
            if (cache[slot].key == key)
                return cache[slot].addr;
            slot = (slot + 1) & (cache_capacity - 1);
            ++probes;
        }

        nt::PVOID module_base = peb::find_module(module_hash);
        if (!module_base)
            return nullptr;

        nt::PVOID addr = pe::find_export(module_base, func_hash);
        if (!addr)
            return nullptr;

        slot = key & (cache_capacity - 1);
        probes = 0;
        while (cache[slot].key != 0 && probes < cache_capacity) {
            slot = (slot + 1) & (cache_capacity - 1);
            ++probes;
        }
        if (probes < cache_capacity) {
            cache[slot].key = key;
            cache[slot].addr = addr;
        }

        return addr;
    }

    template<typename Fn, typename... Args>
    SYSCALL_FORCEINLINE auto call(ImportEntry* cache, unsigned int cache_capacity, unsigned int module_hash, unsigned int func_hash, Args... args) {
        auto addr = resolve(cache, cache_capacity, module_hash, func_hash);
        if (!addr)
            return static_cast<decltype(reinterpret_cast<Fn>(addr)(args...))>(0);
        return reinterpret_cast<Fn>(addr)(args...);
    }

} // namespace syscall::imports
