#include <cstdio>
#include <cstring>
#include <syscall/syscall.h>

static int g_pass = 0;
static int g_fail = 0;

static void check(bool cond, const char* name) {
    if (cond) {
        printf("  PASS  %s\n", name);
        ++g_pass;
    } else {
        printf("  FAIL  %s\n", name);
        ++g_fail;
    }
}

struct MEMORY_BASIC_INFORMATION {
    void* BaseAddress;
    void* AllocationBase;
    unsigned long AllocationProtect;
    unsigned long long RegionSize;
    unsigned long State;
    unsigned long Protect;
    unsigned long Type;
};

using fn_VirtualQuery = unsigned long long (SYSCALL_CALLCONV*)(
    void* lpAddress, MEMORY_BASIC_INFORMATION* lpBuffer, unsigned long long dwLength);

using fn_GetCurrentProcessId = unsigned long (SYSCALL_CALLCONV*)();
using fn_GetCurrentThreadId = unsigned long (SYSCALL_CALLCONV*)();

int main() {
    printf("=== syscall-lib ===\n\n");

    printf("[init]\n");
    syscall::Context ctx{};
    bool init_ok = syscall::Init(ctx);
    check(init_ok, "init succeed");
    if (!init_ok) {
        printf("init failed\n");
        return 1;
    }

    int resolved = 0;
    for (unsigned int i = 0; i < syscall::ssn::kCacheSize; ++i)
        if (ctx.cache[i].hash != 0) ++resolved;
    check(resolved > 400, "resolved syscalls");
    printf("  (%d resolved)\n", resolved);

    printf("\n[ssn]\n");
    struct { const char* name; unsigned int hash; } ssn_targets[] = {
        { "NtAllocateVirtualMemory",  HASH_CT("NtAllocateVirtualMemory")  },
        { "NtFreeVirtualMemory",      HASH_CT("NtFreeVirtualMemory")      },
        { "NtProtectVirtualMemory",   HASH_CT("NtProtectVirtualMemory")   },
        { "NtWriteVirtualMemory",     HASH_CT("NtWriteVirtualMemory")     },
        { "NtOpenProcess",            HASH_CT("NtOpenProcess")            },
        { "NtClose",                  HASH_CT("NtClose")                  },
        { "NtCreateThreadEx",         HASH_CT("NtCreateThreadEx")         },
    };
    for (auto& t : ssn_targets) {
        unsigned short ssn = syscall::GetSSN(ctx, t.hash);
        char buf[64];
        snprintf(buf, sizeof(buf), "SSN(%s) = 0x%04X", t.name, ssn);
        check(ssn != 0xFFFF, buf);
    }

    printf("\n[stub]\n");
    auto* stub_a = static_cast<unsigned char*>(syscall::GetStub(ctx, HASH_CT("NtAllocateVirtualMemory")));
    auto* stub_b = static_cast<unsigned char*>(syscall::GetStub(ctx, HASH_CT("NtClose")));
    check(stub_a != nullptr, "NtAllocateVirtualMemory stub exists");
    check(stub_b != nullptr, "NtClose stub exists");
    if (stub_a && stub_b)
        check(memcmp(stub_a, stub_b, 64) != 0, "stubs have different bytes");

    printf("\n[stub page protection]\n");
    auto vq_fn = reinterpret_cast<fn_VirtualQuery>(
        DYNAMIC_IMPORT(ctx, "kernel32.dll", "VirtualQuery"));
    check(vq_fn != nullptr, "VirtualQuery resolved");
    if (vq_fn) {
        MEMORY_BASIC_INFORMATION mbi{};
        auto result = vq_fn(ctx.stub_page.base, &mbi, sizeof(mbi));
        check(result > 0, "VirtualQuery succeeded");
        check(mbi.Protect == 0x20, "stub page is PAGE_EXECUTE_READ");
        check(mbi.Protect != 0x40, "stub page is not PAGE_EXECUTE_READWRITE");
        printf("  (protect = 0x%02X)\n", mbi.Protect);
    }

    printf("\n[sec_no_change]\n");
    {
        // verify that NtProtectVirtualMemory fails on the stub page
        syscall::nt::PVOID protect_base = ctx.stub_page.base;
        syscall::nt::SIZE_T protect_size = 0x1000;
        syscall::nt::ULONG old_prot = 0;
        auto prot_status = syscall::Invoke<syscall::nt::fn_NtProtectVirtualMemory>(
            ctx, HASH_CT("NtProtectVirtualMemory"),
            reinterpret_cast<syscall::nt::HANDLE>(static_cast<long long>(-1)),
            &protect_base, &protect_size,
            syscall::nt::kPageExecRw, &old_prot);
        check(prot_status != 0, "NtProtectVirtualMemory fails on stub page (SEC_NO_CHANGE)");
        printf("  (status = 0x%08lX)\n", static_cast<unsigned long>(prot_status));
    }

    printf("\n[indirect syscall]\n");
    auto* gadget = static_cast<unsigned char*>(syscall::pe::find_syscall_ret(ctx.ntdll_base));
    auto* ntdll = static_cast<unsigned char*>(ctx.ntdll_base);
    check(gadget != nullptr, "syscall;ret gadget found");
    if (gadget) {
        check(gadget >= ntdll && gadget < ntdll + 0x1000000, "gadget is inside ntdll");
        check(gadget[0] == 0x0F && gadget[1] == 0x05 && gadget[2] == 0xC3, "gadget bytes are syscall;ret");
    }
    if (stub_a) {
        // verify stub contains jmp [rip+0] (FF 25 00 00 00 00)
        bool has_jmp = false;
        for (int i = 0; i + 5 < 64; ++i) {
            if (stub_a[i] == 0xFF && stub_a[i+1] == 0x25 &&
                stub_a[i+2] == 0x00 && stub_a[i+3] == 0x00 &&
                stub_a[i+4] == 0x00 && stub_a[i+5] == 0x00) {
                has_jmp = true;
                break;
            }
        }
        check(has_jmp, "stub uses indirect jmp (no inline syscall)");
    }

    printf("\n[cache encryption]\n");
    unsigned int target_hash = HASH_CT("NtAllocateVirtualMemory");
    bool found_plaintext = false;
    auto* raw = reinterpret_cast<unsigned char*>(ctx.cache);
    unsigned int cache_bytes = sizeof(ctx.cache);
    for (unsigned int i = 0; i <= cache_bytes - 4; ++i) {
        unsigned int val;
        memcpy(&val, raw + i, 4);
        if (val == target_hash) {
            found_plaintext = true;
            break;
        }
    }
    check(!found_plaintext, "no plaintext hash in cache");
    check(ctx.xor_key != 0, "xor key is nonzero");

    printf("\n[syscall invoke]\n");
    void* alloc_addr = nullptr;
    syscall::nt::SIZE_T alloc_size = 0x1000;
    auto alloc_status = syscall::Invoke<syscall::nt::fn_NtAllocateVirtualMemory>(
        ctx, HASH_CT("NtAllocateVirtualMemory"),
        reinterpret_cast<syscall::nt::HANDLE>(static_cast<long long>(-1)),
        &alloc_addr, (syscall::nt::ULONG_PTR)0, &alloc_size,
        syscall::nt::kMemCommit | syscall::nt::kMemReserve,
        syscall::nt::kPageRw);
    check(alloc_status == 0, "NtAllocateVirtualMemory succeeds");
    check(alloc_addr != nullptr, "allocated address is non-null");

    if (alloc_status == 0 && alloc_addr) {
        *static_cast<int*>(alloc_addr) = 42;
        check(*static_cast<int*>(alloc_addr) == 42, "memory read/write works");

        syscall::nt::PVOID protect_addr = alloc_addr;
        syscall::nt::SIZE_T protect_size = alloc_size;
        syscall::nt::ULONG old_protect = 0;
        auto protect_status = syscall::Invoke<syscall::nt::fn_NtProtectVirtualMemory>(
            ctx, HASH_CT("NtProtectVirtualMemory"),
            reinterpret_cast<syscall::nt::HANDLE>(static_cast<long long>(-1)),
            &protect_addr, &protect_size,
            syscall::nt::kPageExecRead, &old_protect);
        check(protect_status == 0, "NtProtectVirtualMemory succeeds");
        check(old_protect == syscall::nt::kPageRw, "old protect was PAGE_READWRITE");

        syscall::nt::PVOID free_addr = alloc_addr;
        syscall::nt::SIZE_T free_size = 0;
        auto free_status = syscall::Invoke<syscall::nt::fn_NtFreeVirtualMemory>(
            ctx, HASH_CT("NtFreeVirtualMemory"),
            reinterpret_cast<syscall::nt::HANDLE>(static_cast<long long>(-1)),
            &free_addr, &free_size, syscall::nt::kMemRelease);
        check(free_status == 0, "NtFreeVirtualMemory succeeds");
    }

    printf("\n[dynamic import]\n");
    auto pid_fn = reinterpret_cast<fn_GetCurrentProcessId>(
        DYNAMIC_IMPORT(ctx, "kernel32.dll", "GetCurrentProcessId"));
    check(pid_fn != nullptr, "GetCurrentProcessId resolved");
    if (pid_fn)
        check(pid_fn() > 0, "GetCurrentProcessId returns valid PID");

    auto tid_fn = reinterpret_cast<fn_GetCurrentThreadId>(
        DYNAMIC_IMPORT(ctx, "kernel32.dll", "GetCurrentThreadId"));
    check(tid_fn != nullptr, "GetCurrentThreadId resolved");
    if (tid_fn)
        check(tid_fn() > 0, "GetCurrentThreadId returns valid TID");

    printf("\n[import cache]\n");
    auto pid_fn2 = reinterpret_cast<fn_GetCurrentProcessId>(
        DYNAMIC_IMPORT(ctx, "kernel32.dll", "GetCurrentProcessId"));
    check(pid_fn == pid_fn2, "cached resolve returns same address");

    printf("\n[forwarded exports]\n");
    auto* heap_alloc = DYNAMIC_IMPORT(ctx, "kernel32.dll", "HeapAlloc");
    check(heap_alloc != nullptr, "kernel32!HeapAlloc resolved");
    if (heap_alloc) {
        auto* ntdll_base = reinterpret_cast<unsigned char*>(ctx.ntdll_base);
        auto* addr = reinterpret_cast<unsigned char*>(heap_alloc);
        bool in_ntdll = (addr >= ntdll_base && addr < ntdll_base + 0x1000000);
        check(in_ntdll, "HeapAlloc forwards into ntdll");
    }

    auto* heap_free = DYNAMIC_IMPORT(ctx, "kernel32.dll", "HeapFree");
    check(heap_free != nullptr, "kernel32!HeapFree resolved");

    printf("\n[init/shutdown cycle]\n");
    syscall::Shutdown(ctx);
    check(true, "first shutdown");

    syscall::Context ctx2{};
    bool reinit = syscall::Init(ctx2);
    check(reinit, "reinit succeeds");
    if (reinit) {
        auto ssn = syscall::GetSSN(ctx2, HASH_CT("NtClose"));
        check(ssn != 0xFFFF, "SSN lookup works after reinit");
        auto* stub = syscall::GetStub(ctx2, HASH_CT("NtClose"));
        check(stub != nullptr, "stub lookup works after reinit");

        void* addr2 = nullptr;
        syscall::nt::SIZE_T sz2 = 0x1000;
        auto st = syscall::Invoke<syscall::nt::fn_NtAllocateVirtualMemory>(
            ctx2, HASH_CT("NtAllocateVirtualMemory"),
            reinterpret_cast<syscall::nt::HANDLE>(static_cast<long long>(-1)),
            &addr2, (syscall::nt::ULONG_PTR)0, &sz2,
            syscall::nt::kMemCommit | syscall::nt::kMemReserve,
            syscall::nt::kPageRw);
        check(st == 0, "syscall works after reinit");
        if (st == 0 && addr2) {
            syscall::nt::PVOID fa = addr2;
            syscall::nt::SIZE_T fs = 0;
            syscall::Invoke<syscall::nt::fn_NtFreeVirtualMemory>(
                ctx2, HASH_CT("NtFreeVirtualMemory"),
                reinterpret_cast<syscall::nt::HANDLE>(static_cast<long long>(-1)),
                &fa, &fs, syscall::nt::kMemRelease);
        }
    }
    syscall::Shutdown(ctx2);

    printf("\n=== results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}
