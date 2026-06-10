#pragma once

#include "nt_defs.h"
#include "intrinsics.h"
#include "peb.h"
#include "pe.h"
#include "hash.h"

namespace syscall::spoof {

    // 256 per-thread slots so concurrent syscalls don't share a stack
    constexpr unsigned int kSlotCount = 256;
    constexpr unsigned int kSlotSize = 256;
    constexpr unsigned int kSlotPivotOffset = 0x80;
    constexpr unsigned int kSpoofRegionSize = kSlotCount * kSlotSize;

    struct SpoofStack {
        nt::PVOID base;
        nt::PVOID stack_top;    // slot 0 pivot, runtime adds thread offset
        nt::HANDLE section;
    };

    constexpr unsigned int kBtiRetOffset = 0x14;
    constexpr unsigned int kRtutsRetOffset = 0x21;

    SYSCALL_FORCEINLINE void write_ptr(nt::BYTE* dst, nt::PVOID val) {
        auto v = reinterpret_cast<unsigned long long>(val);
        volatile unsigned char* p = static_cast<volatile unsigned char*>(dst);
        for (int i = 0; i < 8; ++i)
            p[i] = static_cast<unsigned char>(v >> (i * 8));
    }

    SYSCALL_FORCEINLINE bool init(
        SpoofStack& ss,
        nt::PVOID ntdll_base,
        nt::fn_NtCreateSection fn_create,
        nt::fn_NtMapViewOfSection fn_map,
        nt::fn_NtClose fn_close)
    {
        nt::HANDLE section = nullptr;
        nt::LARGE_INTEGER section_size{};
        section_size.QuadPart = kSpoofRegionSize;

        auto status = fn_create(
            &section, nt::kSectionAllAccess, nullptr,
            &section_size, nt::kPageRw, nt::kSecCommit, nullptr);
        if (status != 0) return false;

        nt::PVOID base = nullptr;
        nt::SIZE_T view_size = 0;
        status = fn_map(
            section,
            reinterpret_cast<nt::HANDLE>(static_cast<long long>(-1)),
            &base, 0, 0, nullptr, &view_size, 2, 0, nt::kPageRw);
        if (status != 0) {
            fn_close(section);
            return false;
        }

        intrinsics::mem_set(base, 0, kSpoofRegionSize);

        auto* frame_base = static_cast<nt::BYTE*>(base);

        auto* k32 = peb::find_module(HASH_CT(L"kernel32.dll"));
        nt::PVOID bti = k32 ? pe::find_export(k32, HASH_CT("BaseThreadInitThunk")) : nullptr;
        nt::PVOID rtuts = pe::find_export(ntdll_base, HASH_CT("RtlUserThreadStart"));

        // write fake frames into every slot
        for (unsigned int slot = 0; slot < kSlotCount; ++slot) {
            auto* pivot = frame_base + slot * kSlotSize + kSlotPivotOffset;
            if (bti)
                write_ptr(pivot + 0x00, static_cast<nt::BYTE*>(bti) + kBtiRetOffset);
            if (rtuts)
                write_ptr(pivot + 0x38, static_cast<nt::BYTE*>(rtuts) + kRtutsRetOffset);
        }

        ss.base = base;
        ss.stack_top = frame_base + kSlotPivotOffset;
        ss.section = section;
        return true;
    }

    SYSCALL_FORCEINLINE void free(
        SpoofStack& ss,
        nt::fn_NtUnmapViewOfSection fn_unmap,
        nt::fn_NtClose fn_close)
    {
        if (ss.base) {
            fn_unmap(
                reinterpret_cast<nt::HANDLE>(static_cast<long long>(-1)),
                ss.base);
        }
        if (ss.section)
            fn_close(ss.section);
        ss.base = nullptr;
        ss.stack_top = nullptr;
        ss.section = nullptr;
    }

} // namespace syscall::spoof
