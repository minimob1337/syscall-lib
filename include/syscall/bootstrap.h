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

    // mov r10,rcx / mov eax,SSN / jmp [rip+0] / <gadget addr>
    #define BOOTSTRAP_STUB { \
        0x4C, 0x8B, 0xD1, \
        0xB8, 0x00, 0x00, 0x00, 0x00, \
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, \
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }

    BSTUB_SECTION static unsigned char stub_create_section[22] = BOOTSTRAP_STUB;
    BSTUB_SECTION static unsigned char stub_map_view[22]       = BOOTSTRAP_STUB;
    BSTUB_SECTION static unsigned char stub_unmap_view[22]     = BOOTSTRAP_STUB;
    BSTUB_SECTION static unsigned char stub_close[22]          = BOOTSTRAP_STUB;

    #undef BOOTSTRAP_STUB
    #undef BSTUB_SECTION

    SYSCALL_FORCEINLINE void patch_ssn(unsigned char* stub, unsigned short ssn) {
        static_cast<volatile unsigned char*>(stub)[4] = static_cast<unsigned char>(ssn & 0xFF);
        static_cast<volatile unsigned char*>(stub)[5] = static_cast<unsigned char>((ssn >> 8) & 0xFF);
    }

    SYSCALL_FORCEINLINE void patch_gadget(unsigned char* stub, nt::PVOID gadget) {
        auto addr = reinterpret_cast<unsigned long long>(gadget);
        volatile unsigned char* p = static_cast<volatile unsigned char*>(stub) + 14;
        for (int i = 0; i < 8; ++i)
            p[i] = static_cast<unsigned char>(addr >> (i * 8));
    }

    SYSCALL_FORCEINLINE nt::fn_NtCreateSection get_create_section() {
        return reinterpret_cast<nt::fn_NtCreateSection>(static_cast<nt::PVOID>(stub_create_section));
    }

    SYSCALL_FORCEINLINE nt::fn_NtMapViewOfSection get_map_view() {
        return reinterpret_cast<nt::fn_NtMapViewOfSection>(static_cast<nt::PVOID>(stub_map_view));
    }

    SYSCALL_FORCEINLINE nt::fn_NtUnmapViewOfSection get_unmap_view() {
        return reinterpret_cast<nt::fn_NtUnmapViewOfSection>(static_cast<nt::PVOID>(stub_unmap_view));
    }

    SYSCALL_FORCEINLINE nt::fn_NtClose get_close() {
        return reinterpret_cast<nt::fn_NtClose>(static_cast<nt::PVOID>(stub_close));
    }

    // restore stub to its original template so bootstrap works on reinit
    SYSCALL_FORCEINLINE void reset_stub(unsigned char* stub) {
        static constexpr unsigned char tmpl[22] = {
            0x4C, 0x8B, 0xD1,
            0xB8, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        volatile unsigned char* p = static_cast<volatile unsigned char*>(stub);
        for (int i = 0; i < 22; ++i)
            p[i] = tmpl[i];
    }

} // namespace syscall::bootstrap
