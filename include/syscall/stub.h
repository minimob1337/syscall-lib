#pragma once

#include "nt_defs.h"
#include "prng.h"

namespace syscall::stub {

    struct StubPage {
        nt::BYTE* base;
        unsigned int used;
        unsigned int capacity;
    };

    constexpr unsigned int kStubSize = 128;
    constexpr unsigned int kPageSize = 4096;
    // 16 pages, enough for 500+ randomized stubs
    constexpr unsigned int kStubRegionSize = kPageSize * 16;
    static_assert(kStubRegionSize / kStubSize - 1 <= 0xFFFE, "max stub offset exceeds unsigned short range");

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

    // writes 0-3 random junk instructions at cursor, returns new cursor
    SYSCALL_FORCEINLINE unsigned int write_junk(volatile unsigned char* p, unsigned int cursor, prng::State& rng, unsigned int limit) {
        unsigned int count = prng::next_range(rng, 4);

        for (unsigned int i = 0; i < count; ++i) {
            unsigned int idx = prng::next_range(rng, kJunkTableSize);
            if (cursor + kJunkTable[idx].len > limit)
                break;
            for (unsigned char b = 0; b < kJunkTable[idx].len; ++b)
                p[cursor++] = kJunkTable[idx].bytes[b];
        }
        return cursor;
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

    SYSCALL_FORCEINLINE unsigned short write_stub(StubPage& page, unsigned short ssn, prng::State& rng, nt::PVOID gadget, nt::PVOID spoof_stack_top) {
        if (page.used + kStubSize > page.capacity)
            return 0xFFFF;

        unsigned short offset = static_cast<unsigned short>(page.used);
        auto* stub = static_cast<unsigned char*>(page.base) + offset;
        volatile unsigned char* p = static_cast<volatile unsigned char*>(stub);
        unsigned int c = 0;

        // fill with int3
        for (unsigned int i = 0; i < kStubSize; ++i)
            p[i] = 0xCC;

        // prologue: push rbx
        p[c++] = 0x53;
        // mov rbx, rsp
        p[c++] = 0x48; p[c++] = 0x89; p[c++] = 0xE3;
        // mov eax, dword ptr gs:[0x48] (thread id from TEB)
        p[c++] = 0x65; p[c++] = 0x8B; p[c++] = 0x04; p[c++] = 0x25;
        p[c++] = 0x48; p[c++] = 0x00; p[c++] = 0x00; p[c++] = 0x00;
        // shr eax, 2 (thread ids are multiples of 4)
        p[c++] = 0xC1; p[c++] = 0xE8; p[c++] = 0x02;
        // movzx eax, al (mask to 256 slots)
        p[c++] = 0x0F; p[c++] = 0xB6; p[c++] = 0xC0;
        // shl eax, 8 (slot index * 256 = slot offset)
        p[c++] = 0xC1; p[c++] = 0xE0; p[c++] = 0x08;
        // mov rsp, [rip+disp32] -> DATA_SPOOF at stub+112 (slot 0 pivot)
        p[c++] = 0x48; p[c++] = 0x8B; p[c++] = 0x25;
        int disp_spoof = 112 - static_cast<int>(c + 4);
        p[c++] = static_cast<unsigned char>(disp_spoof & 0xFF);
        p[c++] = static_cast<unsigned char>((disp_spoof >> 8) & 0xFF);
        p[c++] = static_cast<unsigned char>((disp_spoof >> 16) & 0xFF);
        p[c++] = static_cast<unsigned char>((disp_spoof >> 24) & 0xFF);
        // add rsp, rax (adjust to this thread's slot)
        p[c++] = 0x48; p[c++] = 0x01; p[c++] = 0xC4;

        // push stack args 12 through 5
        static constexpr unsigned char arg_offsets[] = { 0x68, 0x60, 0x58, 0x50, 0x48, 0x40, 0x38, 0x30 };
        for (int i = 0; i < 8; ++i) {
            p[c++] = 0xFF; p[c++] = 0x73; p[c++] = arg_offsets[i];
        }

        // sub rsp, 0x20 (shadow space)
        p[c++] = 0x48; p[c++] = 0x83; p[c++] = 0xEC; p[c++] = 0x20;

        // junk limits: data at 112, remaining fixed bytes after each slot
        // slot 1: mov_r10(3) + mov_eax(5) + call(6) + epilogue(9) = 23
        // slot 2: mov_eax(5) + call(6) + epilogue(9) = 20
        // slot 3: call(6) + epilogue(9) = 15
        c = write_junk(p, c, rng, 112 - 23);
        p[c++] = 0x4C; p[c++] = 0x8B; p[c++] = 0xD1;

        c = write_junk(p, c, rng, 112 - 20);
        p[c++] = 0xB8;
        p[c++] = static_cast<unsigned char>(ssn & 0xFF);
        p[c++] = static_cast<unsigned char>((ssn >> 8) & 0xFF);
        p[c++] = 0x00;
        p[c++] = 0x00;

        c = write_junk(p, c, rng, 112 - 15);
        p[c++] = 0xFF; p[c++] = 0x15;
        int disp_gadget = 120 - static_cast<int>(c + 4);
        p[c++] = static_cast<unsigned char>(disp_gadget & 0xFF);
        p[c++] = static_cast<unsigned char>((disp_gadget >> 8) & 0xFF);
        p[c++] = static_cast<unsigned char>((disp_gadget >> 16) & 0xFF);
        p[c++] = static_cast<unsigned char>((disp_gadget >> 24) & 0xFF);

        // epilogue: add rsp, 0x60 (undo 8 pushes + shadow)
        p[c++] = 0x48; p[c++] = 0x83; p[c++] = 0xC4; p[c++] = 0x60;
        // mov rsp, rbx (restore real stack)
        p[c++] = 0x48; p[c++] = 0x89; p[c++] = 0xDC;
        // pop rbx
        p[c++] = 0x5B;
        // ret
        p[c++] = 0xC3;

        // DATA_SPOOF at stub+112
        {
            auto v = reinterpret_cast<unsigned long long>(spoof_stack_top);
            for (int i = 0; i < 8; ++i)
                p[112 + i] = static_cast<unsigned char>(v >> (i * 8));
        }
        // DATA_GADGET at stub+120
        {
            auto v = reinterpret_cast<unsigned long long>(gadget);
            for (int i = 0; i < 8; ++i)
                p[120 + i] = static_cast<unsigned char>(v >> (i * 8));
        }

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
