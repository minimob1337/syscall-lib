#pragma once

#include "nt_defs.h"

namespace syscall::stub {

    struct StubPage {
        nt::BYTE* base;
        unsigned int used;
        unsigned int capacity;
    };

    constexpr unsigned int kStubSize = 16;
    constexpr unsigned int kPageSize = 4096;
    // 2 pages, enough for ~500 syscalls
    constexpr unsigned int kStubRegionSize = kPageSize * 2;

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

    SYSCALL_FORCEINLINE unsigned short write_stub(StubPage& page, unsigned short ssn) {
        if (page.used + kStubSize > page.capacity)
            return 0xFFFF;

        nt::BYTE* dst = page.base + page.used;


        dst[0] = 0x4C;
        dst[1] = 0x8B;
        dst[2] = 0xD1;

        dst[3] = 0xB8;
        dst[4] = static_cast<nt::BYTE>(ssn & 0xFF);
        dst[5] = static_cast<nt::BYTE>((ssn >> 8) & 0xFF);
        dst[6] = 0x00;
        dst[7] = 0x00;

        dst[8] = 0x0F;
        dst[9] = 0x05;

        dst[10] = 0xC3;

        // int3 padding
        dst[11] = 0xCC;
        dst[12] = 0xCC;
        dst[13] = 0xCC;
        dst[14] = 0xCC;
        dst[15] = 0xCC;

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
