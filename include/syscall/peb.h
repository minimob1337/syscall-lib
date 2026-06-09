#pragma once

#include "hash.h"
#include "nt_defs.h"
#include "intrinsics.h"

#if defined(_MSC_VER) && !defined(__clang__)
extern "C" unsigned long long __readgsqword(unsigned long);
#pragma intrinsic(__readgsqword)
#endif

namespace syscall::peb {

    SYSCALL_FORCEINLINE nt::PEB* get_peb() {
    #if defined(_MSC_VER)
        return reinterpret_cast<nt::PEB*>(__readgsqword(0x60));
    #else
        nt::PEB* peb;
        __asm__ __volatile__("mov %%gs:0x60, %0" : "=r"(peb));
        return peb;
    #endif
    }

    SYSCALL_FORCEINLINE nt::PVOID find_module(unsigned int module_name_hash) {
        nt::PEB* peb = get_peb();
        if (!peb || !peb->Ldr)
            return nullptr;

        nt::LIST_ENTRY* head = &peb->Ldr->InLoadOrderModuleList;
        nt::LIST_ENTRY* current = head->Flink;

        while (current != head) {
            auto* entry = reinterpret_cast<nt::LDR_DATA_TABLE_ENTRY*>(current);

            if (entry->BaseDllName.Buffer) {
                unsigned int h = hash::fnv1a_rt_lower_w(entry->BaseDllName.Buffer);
                if (h == module_name_hash)
                    return entry->DllBase;
            }

            current = current->Flink;
        }

        return nullptr;
    }

} // namespace syscall::peb
