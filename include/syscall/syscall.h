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
#include "bootstrap.h"

namespace syscall {

    struct Context {
        nt::PVOID ntdll_base;
        stub::StubPage stub_page;
        ssn::SsnEntry cache[ssn::kCacheSize];
        unsigned int xor_key;
        imports::ImportEntry import_cache[imports::kImportCacheSize];
        nt::fn_NtUnmapViewOfSection nt_unmap;
        bool initialized;
    };

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

    SYSCALL_FORCEINLINE bool Init(Context& ctx) {
        intrinsics::mem_set(&ctx, 0, sizeof(Context));

        ctx.ntdll_base = peb::find_module(HASH_CT(L"ntdll.dll"));
        if (!ctx.ntdll_base)
            return false;

        prng::State rng{};
        prng::seed(rng);
        ctx.xor_key = prng::next(rng);
        if (ctx.xor_key == 0)
            ctx.xor_key = 0xDEADBEEF;

        ssn::resolve_all(ctx.ntdll_base, ctx.cache, ssn::kCacheSize, ctx.xor_key);
        ssn::verify_ssns(ctx.ntdll_base, ctx.cache, ssn::kCacheSize, ctx.xor_key);

        unsigned short create_ssn = GetSSN(ctx, HASH_CT("NtCreateSection"));
        unsigned short map_ssn = GetSSN(ctx, HASH_CT("NtMapViewOfSection"));
        unsigned short unmap_ssn = GetSSN(ctx, HASH_CT("NtUnmapViewOfSection"));
        unsigned short close_ssn = GetSSN(ctx, HASH_CT("NtClose"));

        if (create_ssn == 0xFFFF || map_ssn == 0xFFFF ||
            unmap_ssn == 0xFFFF || close_ssn == 0xFFFF)
            return false;

        nt::PVOID syscall_gadget = pe::find_syscall_ret(ctx.ntdll_base);
        if (!syscall_gadget)
            return false;

        nt::fn_NtCreateSection fn_create = nullptr;
        nt::fn_NtMapViewOfSection fn_map = nullptr;
        nt::fn_NtUnmapViewOfSection fn_unmap = nullptr;
        nt::fn_NtClose fn_close = nullptr;

        // try bootstrap stubs first (hook-resilient, needs RWX PE section)
        bootstrap::patch_ssn(bootstrap::stub_create_section, create_ssn);
        bootstrap::patch_ssn(bootstrap::stub_map_view, map_ssn);
        bootstrap::patch_ssn(bootstrap::stub_unmap_view, unmap_ssn);
        bootstrap::patch_ssn(bootstrap::stub_close, close_ssn);
        bootstrap::patch_gadget(bootstrap::stub_create_section, syscall_gadget);
        bootstrap::patch_gadget(bootstrap::stub_map_view, syscall_gadget);
        bootstrap::patch_gadget(bootstrap::stub_unmap_view, syscall_gadget);
        bootstrap::patch_gadget(bootstrap::stub_close, syscall_gadget);

        nt::HANDLE section_handle = nullptr;

        if (bootstrap::stub_create_section[0] == 0x4C && bootstrap::stub_create_section[8] == 0xFF) {
            fn_create = bootstrap::get_create_section();
            fn_map = bootstrap::get_map_view();
            fn_unmap = bootstrap::get_unmap_view();
            fn_close = bootstrap::get_close();

            if (stub::alloc_page(ctx.stub_page, section_handle, fn_create, fn_map, fn_close))
                ctx.nt_unmap = fn_unmap;
        }

        // fall back to direct ntdll pointers if bootstrap failed
        if (!ctx.stub_page.base) {
            fn_create = reinterpret_cast<nt::fn_NtCreateSection>(
                pe::find_export(ctx.ntdll_base, HASH_CT("NtCreateSection")));
            fn_map = reinterpret_cast<nt::fn_NtMapViewOfSection>(
                pe::find_export(ctx.ntdll_base, HASH_CT("NtMapViewOfSection")));
            fn_unmap = reinterpret_cast<nt::fn_NtUnmapViewOfSection>(
                pe::find_export(ctx.ntdll_base, HASH_CT("NtUnmapViewOfSection")));
            fn_close = reinterpret_cast<nt::fn_NtClose>(
                pe::find_export(ctx.ntdll_base, HASH_CT("NtClose")));

            if (!fn_create || !fn_map || !fn_unmap || !fn_close)
                return false;
            if (!stub::alloc_page(ctx.stub_page, section_handle, fn_create, fn_map, fn_close))
                return false;

            ctx.nt_unmap = fn_unmap;
        }

        // write stubs to the RW mapped page
        for (unsigned int i = 0; i < ssn::kCacheSize; ++i) {
            if (ctx.cache[i].hash != 0) {
                unsigned short real_ssn = ssn::decrypt_ssn(&ctx.cache[i], ctx.xor_key);
                unsigned short offset = stub::write_stub(ctx.stub_page, real_ssn, rng, syscall_gadget);
                if (offset == 0xFFFF)
                    break;
                ctx.cache[i].stub_offset = offset ^ static_cast<unsigned short>(ctx.xor_key >> 16);
            }
        }

        // unmap RW view and remap as RX with SEC_NO_CHANGE
        if (!stub::finalize_page(ctx.stub_page, section_handle, fn_map, fn_unmap, fn_close))
            return false;

        ctx.initialized = true;
        return true;
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

        if (ctx.nt_unmap)
            stub::free_page(ctx.stub_page, ctx.nt_unmap);

        bootstrap::patch_ssn(bootstrap::stub_create_section, 0);
        bootstrap::patch_ssn(bootstrap::stub_map_view, 0);
        bootstrap::patch_ssn(bootstrap::stub_unmap_view, 0);
        bootstrap::patch_ssn(bootstrap::stub_close, 0);
        bootstrap::patch_gadget(bootstrap::stub_create_section, nullptr);
        bootstrap::patch_gadget(bootstrap::stub_map_view, nullptr);
        bootstrap::patch_gadget(bootstrap::stub_unmap_view, nullptr);
        bootstrap::patch_gadget(bootstrap::stub_close, nullptr);

        intrinsics::secure_zero(&ctx, sizeof(Context));
    }

} // namespace syscall

#define SYSCALL_INVOKE(ctx, NtFuncType, hash, ...) \
    ::syscall::Invoke<NtFuncType>(ctx, hash, __VA_ARGS__)

#define DYNAMIC_IMPORT(ctx, module, func) \
    ::syscall::ResolveImport(ctx, HASH_CT(L##module), HASH_CT(func))

#define DYNAMIC_CALL(ctx, FnType, module, func, ...) \
    ::syscall::DynamicCall<FnType>(ctx, HASH_CT(L##module), HASH_CT(func), __VA_ARGS__)

