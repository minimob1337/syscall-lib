#pragma once

// portable compiler macros
#if defined(__GNUC__) || defined(__clang__)
    #define SYSCALL_FORCEINLINE __attribute__((always_inline)) inline
    #define SYSCALL_CALLCONV
#elif defined(_MSC_VER)
    #define SYSCALL_FORCEINLINE __forceinline
    #define SYSCALL_CALLCONV __stdcall
#else
    #define SYSCALL_FORCEINLINE inline
    #define SYSCALL_CALLCONV
#endif
