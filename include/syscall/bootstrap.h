#pragma once

#include "nt_defs.h"
#include "compiler.h"

#pragma section(".bstub", read, execute)
#pragma comment(linker, "/SECTION:.bstub,RWE")

namespace syscall::bootstrap {

    // rwx stub template: mov r10, rcx / mov eax, SSN / syscall / ret
    #define BOOTSTRAP_STUB { 0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 }

    __declspec(allocate(".bstub")) static unsigned char stub_alloc[]   = BOOTSTRAP_STUB;
    __declspec(allocate(".bstub")) static unsigned char stub_protect[] = BOOTSTRAP_STUB;
    __declspec(allocate(".bstub")) static unsigned char stub_free[]    = BOOTSTRAP_STUB;

    #undef BOOTSTRAP_STUB

    SYSCALL_FORCEINLINE void patch_ssn(unsigned char* stub, unsigned short ssn) {
        stub[4] = static_cast<unsigned char>(ssn & 0xFF);
        stub[5] = static_cast<unsigned char>((ssn >> 8) & 0xFF);
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
