# syscall-lib

Header-only, CRT-free Windows x64 syscall library. Resolves syscall numbers at runtime by parsing ntdll's export table from the PEB, generates unique stubs per call with randomized junk instructions, and caches everything in an XOR-encrypted table.

## Features

- Hook-resilient bootstrap on MSVC/Clang-CL (init uses RWX PE section stubs instead of calling through ntdll)
- PEB walking to find loaded modules
- SSN resolution via Zw* address sorting
- Per-stub randomized junk instructions (every stub has different bytes)
- XOR-encrypted SSN cache
- Forwarded export resolution (follows `kernel32 -> ntdll` chains)
- Dynamic import system for non-syscall WinAPI (`GetCurrentProcessId`, `VirtualQuery`, etc.)
- Fully `consteval` compile-time hashing

## Requirements

- Windows x64
- C++20
- MSVC, Clang-CL, or GNU (Clang/GCC)

## Usage

```cpp
#include <syscall/syscall.h>

syscall::Context ctx{};
syscall::Init(ctx);

// direct syscall
void* addr = nullptr;
SIZE_T size = 0x1000;
syscall::Invoke<fn_NtAllocateVirtualMemory>(
    ctx, HASH_CT("NtAllocateVirtualMemory"),
    NtCurrentProcess(), &addr, 0, &size,
    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

// dynamic import (non-syscall WinAPI)
auto pid = DYNAMIC_CALL(ctx, fn_GetCurrentProcessId,
    "kernel32.dll", "GetCurrentProcessId");

syscall::Shutdown(ctx);
```

## How it works

1. **Init** - walks the PEB to find ntdll, parses its export table, sorts Zw* exports by address to derive SSNs. On MSVC/Clang-CL, patches bootstrap stubs in a RWX PE section to allocate memory without ever calling through ntdll. On GNU, falls back to direct ntdll function pointers for the initial allocation. Then generates a unique assembly stub for each syscall with random junk instructions and flips the stub page to `PAGE_EXECUTE_READ`
2. **Invoke** - looks up the SSN from the encrypted cache, finds the corresponding stub, calls it directly (the stub does `mov r10,rcx / mov eax,SSN / syscall / ret` with junk bytes mixed in)
3. **Shutdown** - securely zeros all context memory and frees the stub page

## Project structure

```
include/syscall/
  syscall.h          - main API (Init, Invoke, Shutdown, macros)
  hash.h             - FNV-1a compile-time + runtime hashing
  nt_defs.h          - NT type definitions
  peb.h              - PEB module enumeration
  pe.h               - PE export table parsing + forwarded exports
  ssn.h              - SSN resolution + encrypted cache
  stub.h             - stub generation with junk instructions
  bootstrap.h        - RWX PE section bootstrap stubs for hook-free init
  prng.h             - xorshift32 PRNG
  intrinsics.h       - CRT-free memory primitives
  dynamic_import.h   - non-syscall import resolution + cache
  compiler.h         - portable compiler macros
test/
  main.cpp           - basic tests
```
