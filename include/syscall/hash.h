#pragma once

#include "compiler.h"

namespace syscall::hash {

    constexpr unsigned int fnv1a_basis = 0x811C9DC5;
    constexpr unsigned int fnv1a_prime = 0x01000193;

    template<unsigned int N>
    consteval unsigned int fnv1a_ct(const char (&str)[N]) {
        unsigned int hash = fnv1a_basis;
        for (unsigned int i = 0; i < N - 1; ++i) {
            hash ^= static_cast<unsigned char>(str[i]);
            hash *= fnv1a_prime;
        }
        return hash;
    }

    template<unsigned int N>
    consteval unsigned int fnv1a_ct(const wchar_t (&str)[N]) {
        unsigned int hash = fnv1a_basis;
        for (unsigned int i = 0; i < N - 1; ++i) {
            wchar_t c = str[i];
            if (c >= L'A' && c <= L'Z')
                c |= 0x20;

            unsigned char lo = static_cast<unsigned char>(c & 0xFF);
            unsigned char hi = static_cast<unsigned char>((c >> 8) & 0xFF);

            hash ^= lo;
            hash *= fnv1a_prime;
            hash ^= hi;
            hash *= fnv1a_prime;
        }
        return hash;
    }

    SYSCALL_FORCEINLINE unsigned int fnv1a_rt(const char* str) {
        unsigned int hash = fnv1a_basis;
        while (*str) {
            hash ^= static_cast<unsigned char>(*str);
            hash *= fnv1a_prime;
            ++str;
        }
        return hash;
    }

    SYSCALL_FORCEINLINE unsigned int fnv1a_rt_lower_w(const wchar_t* str) {
        unsigned int hash = fnv1a_basis;
        while (*str) {
            wchar_t c = *str;
            if (c >= L'A' && c <= L'Z')
                c |= 0x20;

            unsigned char lo = static_cast<unsigned char>(c & 0xFF);
            unsigned char hi = static_cast<unsigned char>((c >> 8) & 0xFF);

            hash ^= lo;
            hash *= fnv1a_prime;
            hash ^= hi;
            hash *= fnv1a_prime;

            ++str;
        }
        return hash;
    }

} // namespace syscall::hash

#define HASH_CT(str) (::syscall::hash::fnv1a_ct(str))
