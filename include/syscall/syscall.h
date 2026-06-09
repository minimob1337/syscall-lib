#pragma once

#include "hash.h"
#include "nt_defs.h"
#include "intrinsics.h"
#include "peb.h"
#include "pe.h"
#include "ssn.h"
#include "stub.h"
#include "prng.h"
#include "dynamic_import.h"

namespace syscall {

    struct Context {
        nt::PVOID ntdll_base;
        stub::StubPage stub_page;
        ssn::SsnEntry cache[ssn::kCacheSize];
        nt::fn_NtFreeVirtualMemory nt_free;
        unsigned int xor_key;
        imports::ImportEntry import_cache[imports::kImportCacheSize];
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

        prng::State rng{};
        prng::seed(rng);
        ctx.xor_key = prng::next(rng);
        if (ctx.xor_key == 0)
            ctx.xor_key = 0xDEADBEEF;

        ssn::resolve_all(ctx.ntdll_base, ctx.cache, ssn::kCacheSize, ctx.xor_key);

        for (unsigned int i = 0; i < ssn::kCacheSize; ++i) {
            if (ctx.cache[i].hash != 0) {
                unsigned short real_ssn = ssn::decrypt_ssn(&ctx.cache[i], ctx.xor_key);
                unsigned short offset = stub::write_stub(ctx.stub_page, real_ssn, rng);
                if (offset == 0xFFFF)
                    break;
                ctx.cache[i].stub_offset = offset ^ static_cast<unsigned short>(ctx.xor_key >> 16);
            }
        }

        if (!stub::protect_page(ctx.stub_page, nt_protect))
            return false;

        ctx.initialized = true;
        return true;
    }

    SYSCALL_FORCEINLINE nt::PVOID GetStub(const Context& ctx, unsigned int nt_hash) {
        auto* entry = ssn::lookup(
            const_cast<ssn::SsnEntry*>(ctx.cache), ssn::kCacheSize, nt_hash, ctx.xor_key);
        if (!entry)
            return nullptr;
        unsigned short real_offset = ssn::decrypt_offset(entry, ctx.xor_key);
        return stub::get_stub(ctx.stub_page, real_offset);
    }

    SYSCALL_FORCEINLINE unsigned short GetSSN(const Context& ctx, unsigned int nt_hash) {
        auto* entry = ssn::lookup(
            const_cast<ssn::SsnEntry*>(ctx.cache), ssn::kCacheSize, nt_hash, ctx.xor_key);
        if (!entry)
            return 0xFFFF;
        return ssn::decrypt_ssn(entry, ctx.xor_key);
    }

    template<typename Fn, typename... Args>
    SYSCALL_FORCEINLINE auto Invoke(const Context& ctx, unsigned int nt_hash, Args... args) {
        auto stub = GetStub(ctx, nt_hash);
        if (!stub)
            return static_cast<decltype(reinterpret_cast<Fn>(stub)(args...))>(0xC0000001);
        return reinterpret_cast<Fn>(stub)(args...);
    }

    SYSCALL_FORCEINLINE nt::PVOID ResolveImport(Context& ctx, unsigned int module_hash, unsigned int func_hash) {
        return imports::resolve(ctx.import_cache, imports::kImportCacheSize, module_hash, func_hash);
    }

    template<typename Fn, typename... Args>
    SYSCALL_FORCEINLINE auto DynamicCall(Context& ctx, unsigned int module_hash, unsigned int func_hash, Args... args) {
        return imports::call<Fn>(ctx.import_cache, imports::kImportCacheSize, module_hash, func_hash, args...);
    }

    SYSCALL_FORCEINLINE void Shutdown(Context& ctx) {
        if (!ctx.initialized)
            return;

        if (ctx.nt_free)
            stub::free_page(ctx.stub_page, ctx.nt_free);

        intrinsics::secure_zero(&ctx, sizeof(Context));
    }

} // namespace syscall

#define SYSCALL_INVOKE(ctx, NtFuncType, hash, ...) \
    ::syscall::Invoke<NtFuncType>(ctx, hash, __VA_ARGS__)

#define DYNAMIC_IMPORT(ctx, module, func) \
    ::syscall::ResolveImport(ctx, HASH_CT(L##module), HASH_CT(func))

#define DYNAMIC_CALL(ctx, FnType, module, func, ...) \
    ::syscall::DynamicCall<FnType>(ctx, HASH_CT(L##module), HASH_CT(func), __VA_ARGS__)

