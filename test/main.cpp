#include <cstdio>
#include <syscall/syscall.h>

int main() {
    printf("=== syscall-lib ===\n\n");

    syscall::Context ctx{};
    if (!syscall::Init(ctx)) {
        printf("init failed\n");
        return 1;
    }

    int resolved = 0;
    for (int i = 0; i < (int)syscall::ssn::kCacheSize; ++i) {
        if (ctx.cache[i].hash != 0)
            ++resolved;
    }
    printf("resolved %d syscalls\n", resolved);
    printf("stub page: %p, used: %u / %u bytes\n",
           ctx.stub_page.base, ctx.stub_page.used, ctx.stub_page.capacity);

    printf("\n--- SSN Table ---\n");
    struct { const char* name; unsigned int hash; } targets[] = {
        { "NtAllocateVirtualMemory",  HASH_CT("NtAllocateVirtualMemory")  },
        { "NtFreeVirtualMemory",      HASH_CT("NtFreeVirtualMemory")      },
        { "NtProtectVirtualMemory",   HASH_CT("NtProtectVirtualMemory")   },
        { "NtWriteVirtualMemory",     HASH_CT("NtWriteVirtualMemory")     },
        { "NtOpenProcess",            HASH_CT("NtOpenProcess")            },
        { "NtClose",                  HASH_CT("NtClose")                  },
        { "NtCreateThreadEx",         HASH_CT("NtCreateThreadEx")         },
    };
    for (auto& t : targets) {
        auto* entry = syscall::ssn::lookup(ctx.cache, syscall::ssn::kCacheSize, t.hash);
        if (entry)
            printf("  %-30s SSN=0x%04X\n", t.name, entry->ssn);
        else
            printf("  %-30s NOT FOUND\n", t.name);
    }

    printf("\n--- stub hex dump ---\n");
    struct { const char* name; unsigned int hash; } dump_targets[] = {
        { "NtAllocateVirtualMemory", HASH_CT("NtAllocateVirtualMemory") },
        { "NtClose",                 HASH_CT("NtClose")                 },
    };
    for (auto& t : dump_targets) {
        auto* stub_ptr = static_cast<unsigned char*>(syscall::GetStub(ctx, t.hash));
        if (stub_ptr) {
            printf("  %s:\n    ", t.name);
            for (int b = 0; b < 64; ++b) {
                printf("%02X ", stub_ptr[b]);
                if ((b + 1) % 16 == 0 && b < 63)
                    printf("\n    ");
            }
            printf("\n");
        }
    }

    printf("\n--- NtAllocateVirtualMemory ---\n");
    void* alloc_addr = nullptr;
    syscall::nt::SIZE_T alloc_size = 0x1000;
    auto status = syscall::Invoke<syscall::nt::fn_NtAllocateVirtualMemory>(
        ctx, HASH_CT("NtAllocateVirtualMemory"),
        reinterpret_cast<syscall::nt::HANDLE>(static_cast<long long>(-1)),
        &alloc_addr, (syscall::nt::ULONG_PTR)0, &alloc_size,
        syscall::nt::MEM_COMMIT | syscall::nt::MEM_RESERVE,
        syscall::nt::PAGE_READWRITE);
    printf("status: 0x%08X, addr: %p\n", (unsigned int)status, alloc_addr);

    if (status == 0 && alloc_addr) {
        *static_cast<int*>(alloc_addr) = 42;
        printf("wrote 42, read back: %d\n", *static_cast<int*>(alloc_addr));

        // Free
        syscall::nt::SIZE_T free_size = 0;
        auto free_status = syscall::Invoke<syscall::nt::fn_NtFreeVirtualMemory>(
            ctx, HASH_CT("NtFreeVirtualMemory"),
            reinterpret_cast<syscall::nt::HANDLE>(static_cast<long long>(-1)),
            &alloc_addr, &free_size, syscall::nt::MEM_RELEASE);
        printf("NtFreeVirtualMemory: 0x%08X\n", (unsigned int)free_status);
    } else {
        printf("allocation failed\n");
    }

    // Verify stub page is RX (not RWX)
    printf("\n--- stub Page Protection ---\n");
    printf("stub page at %p should be PAGE_EXECUTE_READ (0x20) after init\n",
           ctx.stub_page.base);

    syscall::Shutdown(ctx);
    return 0;
}
