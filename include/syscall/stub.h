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
    static_assert(kStubRegionSize - kStubSize <= 0xFFFE, "max stub offset exceeds unsigned short range");

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

    // create section and map RW view for writing stubs
    SYSCALL_FORCEINLINE bool alloc_page(
        StubPage& page,
        nt::HANDLE& section_handle_out,
        nt::fn_NtCreateSection fn_create,
        nt::fn_NtMapViewOfSection fn_map,
        nt::fn_NtClose fn_close)
    {
        nt::HANDLE current_process = reinterpret_cast<nt::HANDLE>(static_cast<long long>(-1));

        // create a section backed by the pagefile
        nt::LARGE_INTEGER section_size{};
        section_size.QuadPart = kStubRegionSize;
        section_handle_out = nullptr;

        nt::NTSTATUS status = fn_create(
            &section_handle_out,
            nt::kSectionAllAccess,
            nullptr,
            &section_size,
            nt::kPageExecRw,
            nt::kSecCommit | nt::kSecNoChange,
            nullptr);

        if (status != nt::kStatusSuccess)
            return false;

        // map RW view for writing stubs
        nt::PVOID rw_base = nullptr;
        nt::SIZE_T view_size = 0;

        status = fn_map(
            section_handle_out,
            current_process,
            &rw_base,
            0,
            0,
            nullptr,
            &view_size,
            nt::kViewUnmap,
            0,
            nt::kPageRw);

        if (status != nt::kStatusSuccess) {
            fn_close(section_handle_out);
            return false;
        }

        page.base = static_cast<nt::BYTE*>(rw_base);
        page.used = 0;
        page.capacity = kStubRegionSize;

        return true;
    }

    // unmap RW view and remap as RX with SEC_NO_CHANGE
    SYSCALL_FORCEINLINE bool finalize_page(
        StubPage& page,
        nt::HANDLE section_handle,
        nt::fn_NtMapViewOfSection fn_map,
        nt::fn_NtUnmapViewOfSection fn_unmap,
        nt::fn_NtClose fn_close)
    {
        nt::HANDLE current_process = reinterpret_cast<nt::HANDLE>(static_cast<long long>(-1));

        // unmap the RW view
        nt::NTSTATUS status = fn_unmap(current_process, page.base);
        if (status != nt::kStatusSuccess) {
            fn_close(section_handle);
            return false;
        }

        // remap as RX, edr cannot change protection on this view
        nt::PVOID rx_base = nullptr;
        nt::SIZE_T view_size = 0;

        status = fn_map(
            section_handle,
            current_process,
            &rx_base,
            0,
            0,
            nullptr,
            &view_size,
            nt::kViewUnmap,
            0,
            nt::kPageExecRead);

        // close the section handle, view stays mapped
        fn_close(section_handle);

        if (status != nt::kStatusSuccess) {
            page.base = nullptr;
            return false;
        }

        page.base = static_cast<nt::BYTE*>(rx_base);
        return true;
    }

    SYSCALL_FORCEINLINE unsigned short write_stub(StubPage& page, unsigned short ssn, prng::State& rng, nt::PVOID syscall_gadget) {
        if (page.used + kStubSize > page.capacity)
            return 0xFFFF;

        nt::BYTE* dst = page.base + page.used;
        unsigned int pos = 0;

        pos += write_junk(dst + pos, rng);

        // mov r10, rcx
        dst[pos++] = 0x4C;
        dst[pos++] = 0x8B;
        dst[pos++] = 0xD1;

        pos += write_junk(dst + pos, rng);

        // mov eax, SSN
        dst[pos++] = 0xB8;
        dst[pos++] = static_cast<nt::BYTE>(ssn & 0xFF);
        dst[pos++] = static_cast<nt::BYTE>((ssn >> 8) & 0xFF);
        dst[pos++] = 0x00;
        dst[pos++] = 0x00;

        pos += write_junk(dst + pos, rng);

        // jmp qword ptr [rip+0] -> lands on gadget addr below
        dst[pos++] = 0xFF;
        dst[pos++] = 0x25;
        dst[pos++] = 0x00;
        dst[pos++] = 0x00;
        dst[pos++] = 0x00;
        dst[pos++] = 0x00;

        // inline gadget address (syscall;ret inside ntdll)
        auto addr = reinterpret_cast<unsigned long long>(syscall_gadget);
        for (int i = 0; i < 8; ++i)
            dst[pos++] = static_cast<nt::BYTE>((addr >> (i * 8)) & 0xFF);

        // int3 padding
        while (pos < kStubSize)
            dst[pos++] = 0xCC;

        unsigned short offset = static_cast<unsigned short>(page.used);
        page.used += kStubSize;
        return offset;
    }

    SYSCALL_FORCEINLINE bool free_page(StubPage& page, nt::fn_NtUnmapViewOfSection fn_unmap) {
        nt::HANDLE current_process = reinterpret_cast<nt::HANDLE>(static_cast<long long>(-1));

        nt::NTSTATUS status = fn_unmap(current_process, page.base);

        page.base = nullptr;
        page.used = 0;
        page.capacity = 0;
        return status == nt::kStatusSuccess;
    }

    SYSCALL_FORCEINLINE nt::PVOID get_stub(const StubPage& page, unsigned short offset) {
        return page.base + offset;
    }

} // namespace syscall::stub
