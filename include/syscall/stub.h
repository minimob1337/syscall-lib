#pragma once

#include "nt_defs.h"
#include "prng.h"

namespace syscall::stub {

    struct StubPage {
        nt::BYTE* base;
        unsigned int used;
        unsigned int capacity;
    };

    constexpr unsigned int kStubSize = 64;
    constexpr unsigned int kPageSize = 4096;
    // 16 pages, enough for 500+ randomized stubs
    constexpr unsigned int kStubRegionSize = kPageSize * 16;

    struct JunkInsn {
        nt::BYTE bytes[4];
        unsigned char len;
    };

    constexpr unsigned int kJunkTableSize = 7;
    constexpr JunkInsn kJunkTable[kJunkTableSize] = {
        {{0x90, 0x00, 0x00, 0x00}, 1},             // nop
        {{0x66, 0x90, 0x00, 0x00}, 2},             // 2-byte nop
        {{0x0F, 0x1F, 0x00, 0x00}, 3},             // 3-byte nop
        {{0x0F, 0x1F, 0x40, 0x00}, 4},             // 4-byte nop
        {{0x48, 0x87, 0xDB, 0x00}, 3},             // xchg rbx, rbx
        {{0x48, 0x87, 0xF6, 0x00}, 3},             // xchg rsi, rsi
        {{0x48, 0x87, 0xFF, 0x00}, 3},             // xchg rdi, rdi
    };

    // writes 0-3 random junk instructions, returns bytes written
    SYSCALL_FORCEINLINE unsigned int write_junk(nt::BYTE* dst, prng::State& rng) {
        unsigned int count = prng::next_range(rng, 4);
        unsigned int written = 0;

        for (unsigned int i = 0; i < count; ++i) {
            unsigned int idx = prng::next_range(rng, kJunkTableSize);
            for (unsigned char b = 0; b < kJunkTable[idx].len; ++b)
                dst[written++] = kJunkTable[idx].bytes[b];
        }
        return written;
    }

    SYSCALL_FORCEINLINE bool alloc_page(StubPage& page, nt::fn_NtAllocateVirtualMemory nt_alloc) {
        nt::PVOID base_addr = nullptr;
        nt::SIZE_T region_size = kStubRegionSize;

        nt::NTSTATUS status = nt_alloc(
            reinterpret_cast<nt::HANDLE>(static_cast<long long>(-1)),
            &base_addr,
            0,
            &region_size,
            nt::MEM_COMMIT | nt::MEM_RESERVE,
            nt::PAGE_READWRITE);

        if (status != nt::STATUS_SUCCESS)
            return false;

        page.base = static_cast<nt::BYTE*>(base_addr);
        page.used = 0;
        page.capacity = kStubRegionSize;
        return true;
    }

    SYSCALL_FORCEINLINE unsigned short write_stub(StubPage& page, unsigned short ssn, prng::State& rng) {
        if (page.used + kStubSize > page.capacity)
            return 0xFFFF;

        nt::BYTE* dst = page.base + page.used;
        unsigned int pos = 0;

        // junk before mov r10, rcx
        pos += write_junk(dst + pos, rng);

        // mov r10, rcx
        dst[pos++] = 0x4C;
        dst[pos++] = 0x8B;
        dst[pos++] = 0xD1;

        // junk before mov eax, ssn
        pos += write_junk(dst + pos, rng);

        // mov eax, SSN
        dst[pos++] = 0xB8;
        dst[pos++] = static_cast<nt::BYTE>(ssn & 0xFF);
        dst[pos++] = static_cast<nt::BYTE>((ssn >> 8) & 0xFF);
        dst[pos++] = 0x00;
        dst[pos++] = 0x00;

        // junk before syscall
        pos += write_junk(dst + pos, rng);

        // syscall
        dst[pos++] = 0x0F;
        dst[pos++] = 0x05;

        // ret
        dst[pos++] = 0xC3;

        // int3 padding
        while (pos < kStubSize)
            dst[pos++] = 0xCC;

        unsigned short offset = static_cast<unsigned short>(page.used);
        page.used += kStubSize;
        return offset;
    }

    SYSCALL_FORCEINLINE bool protect_page(StubPage& page, nt::fn_NtProtectVirtualMemory nt_protect) {
        nt::PVOID base_addr = page.base;
        nt::SIZE_T region_size = page.capacity;
        nt::ULONG old_protect = 0;

        nt::NTSTATUS status = nt_protect(
            reinterpret_cast<nt::HANDLE>(static_cast<long long>(-1)),
            &base_addr,
            &region_size,
            nt::PAGE_EXECUTE_READ,
            &old_protect);

        return status == nt::STATUS_SUCCESS;
    }

    SYSCALL_FORCEINLINE bool free_page(StubPage& page, nt::fn_NtFreeVirtualMemory nt_free) {
        nt::PVOID base_addr = page.base;
        nt::SIZE_T region_size = 0;

        nt::NTSTATUS status = nt_free(
            reinterpret_cast<nt::HANDLE>(static_cast<long long>(-1)),
            &base_addr,
            &region_size,
            nt::MEM_RELEASE);

        page.base = nullptr;
        page.used = 0;
        page.capacity = 0;
        return status == nt::STATUS_SUCCESS;
    }

    SYSCALL_FORCEINLINE nt::PVOID get_stub(const StubPage& page, unsigned short offset) {
        return page.base + offset;
    }

} // namespace syscall::stub
