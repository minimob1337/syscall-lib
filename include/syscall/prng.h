#pragma once

#include "compiler.h"
#include "nt_defs.h"

#if defined(_MSC_VER)
extern "C" unsigned __int64 __rdtsc();
#pragma intrinsic(__rdtsc)
#endif

namespace syscall::prng {

    struct State {
        unsigned int s;
    };

    SYSCALL_FORCEINLINE void seed(State& state) {
        unsigned long long tsc;
    #if defined(_MSC_VER)
        tsc = __rdtsc();
    #else
        unsigned int lo, hi;
        __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
        tsc = (static_cast<unsigned long long>(hi) << 32) | lo;
    #endif
        state.s = static_cast<unsigned int>(tsc ^ (tsc >> 16));
        if (state.s == 0)
            state.s = 0xDEADBEEF;
    }

    SYSCALL_FORCEINLINE unsigned int next(State& state) {
        unsigned int x = state.s;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        state.s = x;
        return x;
    }

    SYSCALL_FORCEINLINE unsigned int next_range(State& state, unsigned int max) {
        return next(state) % max;
    }

} // namespace syscall::prng
