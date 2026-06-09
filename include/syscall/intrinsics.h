#pragma once

#include "compiler.h"

namespace syscall::intrinsics {

    SYSCALL_FORCEINLINE void* mem_copy(void* dst, const void* src, unsigned long long n) {
        auto* d = static_cast<unsigned char*>(dst);
        auto* s = static_cast<const unsigned char*>(src);
        for (unsigned long long i = 0; i < n; ++i)
            d[i] = s[i];
        return dst;
    }

    SYSCALL_FORCEINLINE void* mem_set(void* dst, int val, unsigned long long n) {
        auto* d = static_cast<unsigned char*>(dst);
        auto v = static_cast<unsigned char>(val);
        for (unsigned long long i = 0; i < n; ++i)
            d[i] = v;
        return dst;
    }

    SYSCALL_FORCEINLINE int mem_cmp(const void* a, const void* b, unsigned long long n) {
        auto* pa = static_cast<const unsigned char*>(a);
        auto* pb = static_cast<const unsigned char*>(b);
        for (unsigned long long i = 0; i < n; ++i) {
            if (pa[i] != pb[i])
                return pa[i] < pb[i] ? -1 : 1;
        }
        return 0;
    }

    SYSCALL_FORCEINLINE unsigned long long str_len(const char* s) {
        unsigned long long len = 0;
        while (s[len])
            ++len;
        return len;
    }

    SYSCALL_FORCEINLINE unsigned long long wstr_len(const wchar_t* s) {
        unsigned long long len = 0;
        while (s[len])
            ++len;
        return len;
    }

    SYSCALL_FORCEINLINE bool str_starts_with(const char* s, const char* prefix) {
        while (*prefix) {
            if (*s != *prefix)
                return false;
            ++s;
            ++prefix;
        }
        return true;
    }

    SYSCALL_FORCEINLINE int str_cmp(const char* a, const char* b) {
        while (*a && *a == *b) {
            ++a;
            ++b;
        }
        return static_cast<unsigned char>(*a) - static_cast<unsigned char>(*b);
    }

} // namespace syscall::intrinsics
