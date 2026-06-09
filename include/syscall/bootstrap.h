#pragma once

#include "nt_defs.h"
#include "compiler.h"

#if defined(_MSC_VER)
    #pragma section(".bstub", read, execute)
    #pragma comment(linker, "/SECTION:.bstub,RWE")
    #define BSTUB_SECTION __declspec(allocate(".bstub"))
#elif defined(__GNUC__) || defined(__clang__)
    // pre-declare section with execute+write flags before any attribute usage
    asm(".section .bstub, \"xw\"\n\t.text");
    #define BSTUB_SECTION __attribute__((section(".bstub"), used))
#else
    #error "unsupported compiler for bootstrap stubs"
#endif

namespace syscall::bootstrap {

    // rwx stub template: mov r10, rcx / mov eax, SSN / syscall / ret
    #define BOOTSTRAP_STUB { 0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 }

    BSTUB_SECTION static unsigned char stub_alloc[]   = BOOTSTRAP_STUB;
    BSTUB_SECTION static unsigned char stub_protect[] = BOOTSTRAP_STUB;
    BSTUB_SECTION static unsigned char stub_free[]    = BOOTSTRAP_STUB;

    #undef BOOTSTRAP_STUB
    #undef BSTUB_SECTION

    SYSCALL_FORCEINLINE void patch_ssn(unsigned char* stub, unsigned short ssn) {
        static_cast<volatile unsigned char*>(stub)[4] = static_cast<unsigned char>(ssn & 0xFF);
        static_cast<volatile unsigned char*>(stub)[5] = static_cast<unsigned char>((ssn >> 8) & 0xFF);
    }

    SYSCALL_FORCEINLINE nt::fn_NtAllocateVirtualMemory get_alloc() {
        return reinterpret_cast<nt::fn_NtAllocateVirtualMemory>(static_cast<nt::PVOID>(stub_alloc));
    }

    SYSCALL_FORCEINLINE nt::fn_NtProtectVirtualMemory get_protect() {
        return reinterpret_cast<nt::fn_NtProtectVirtualMemory>(static_cast<nt::PVOID>(stub_protect));
    }

    SYSCALL_FORCEINLINE nt::fn_NtFreeVirtualMemory get_free() {
        return reinterpret_cast<nt::fn_NtFreeVirtualMemory>(static_cast<nt::PVOID>(stub_free));
    }

} // namespace syscall::bootstrap
