#pragma once

#include "hash.h"
#include "nt_defs.h"
#include "intrinsics.h"
#include "peb.h"
#include "pe.h"
#include "ssn.h"
#include "stub.h"

namespace syscall {

    struct Context {
        nt::PVOID ntdll_base;
        stub::StubPage stub_page;
        ssn::SsnEntry cache[ssn::kCacheSize];
        nt::fn_NtFreeVirtualMemory nt_free;
        bool initialized;
    };

    SYSCALL_FORCEINLINE bool Init(Context& ctx) {
        intrinsics::mem_set(&ctx, 0, sizeof(Context));

        ctx.ntdll_base = peb::find_module(HASH_CT(L"ntdll.dll"));
        if (!ctx.ntdll_base)
            return false;

        auto nt_alloc = reinterpret_cast<nt::fn_NtAllocateVirtualMemory>(
            pe::find_export(ctx.ntdll_base, HASH_CT("NtAllocateVirtualMemory")));
        auto nt_protect = reinterpret_cast<nt::fn_NtProtectVirtualMemory>(
            pe::find_export(ctx.ntdll_base, HASH_CT("NtProtectVirtualMemory")));
        ctx.nt_free = reinterpret_cast<nt::fn_NtFreeVirtualMemory>(
            pe::find_export(ctx.ntdll_base, HASH_CT("NtFreeVirtualMemory")));

        if (!nt_alloc || !nt_protect || !ctx.nt_free)
            return false;

        if (!stub::alloc_page(ctx.stub_page, nt_alloc))
            return false;

        ssn::resolve_all(ctx.ntdll_base, ctx.cache, ssn::kCacheSize);

        for (unsigned int i = 0; i < ssn::kCacheSize; ++i) {
            if (ctx.cache[i].hash != 0) {
                unsigned short offset = stub::write_stub(ctx.stub_page, ctx.cache[i].ssn);
                ctx.cache[i].stub_offset = offset;
            }
        }

        if (!stub::protect_page(ctx.stub_page, nt_protect))
            return false;

        ctx.initialized = true;
        return true;
    }

    SYSCALL_FORCEINLINE nt::PVOID GetStub(const Context& ctx, unsigned int nt_hash) {
        auto* entry = ssn::lookup(
            const_cast<ssn::SsnEntry*>(ctx.cache), ssn::kCacheSize, nt_hash);
        if (!entry)
            return nullptr;
        return stub::get_stub(ctx.stub_page, entry->stub_offset);
    }

    template<typename Fn, typename... Args>
    SYSCALL_FORCEINLINE auto Invoke(const Context& ctx, unsigned int nt_hash, Args... args) {
        auto fn = reinterpret_cast<Fn>(GetStub(ctx, nt_hash));
        return fn(args...);
    }

    SYSCALL_FORCEINLINE void Shutdown(Context& ctx) {
        if (!ctx.initialized)
            return;

        if (ctx.nt_free)
            stub::free_page(ctx.stub_page, ctx.nt_free);

        intrinsics::mem_set(&ctx, 0, sizeof(Context));
    }

} // namespace syscall

#define SYSCALL_INVOKE(ctx, NtFuncType, hash, ...) \
    ::syscall::Invoke<NtFuncType>(ctx, hash, __VA_ARGS__)
