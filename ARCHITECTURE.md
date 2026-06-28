# Qiling Framework Architecture

Qiling is a cross-platform, multi-architecture binary emulation framework built on top of the [Unicorn](https://www.unicorn-engine.org/) CPU emulation engine. It adds OS-level abstractions (syscalls, file systems, loaders) on top of raw CPU emulation, enabling full binary execution without native hardware.

## High-Level Overview

```
┌──────────────────────────────────────────────────┐
│                 User Script / qltool              │
├──────────────────────────────────────────────────┤
│              Qiling Core (core.py)                │
│         hooks · state snapshots · patches         │
├────────────┬─────────────┬───────────────────────┤
│  OS Layer  │   Loader    │   Memory Manager      │
│  (QlOs)    │  (QlLoader) │  (QlMemoryManager)    │
│  syscalls  │  ELF/PE/    │  map · read · write   │
│  APIs      │  MachO/etc  │  MMIO callbacks       │
├────────────┴─────────────┴───────────────────────┤
│         Architecture Layer (QlArch)               │
│     registers · disassembly · calling conventions │
├──────────────────────────────────────────────────┤
│              Unicorn Engine (CPU)                  │
│          instruction-level emulation              │
└──────────────────────────────────────────────────┘
```

## Directory Structure

```
qiling/
├── qiling/                 # Core framework package
│   ├── core.py             # Qiling class — main entry point and orchestrator
│   ├── core_hooks.py       # Hook system (code, memory, interrupt, address hooks)
│   ├── core_hooks_types.py # Hook type definitions and dispatch
│   ├── core_struct.py      # Endian-aware struct packing utilities
│   ├── const.py            # Enumerations: QL_ARCH, QL_OS, QL_ENDIAN, etc.
│   ├── exception.py        # Custom exception hierarchy
│   ├── utils.py            # Component selection (select_arch, select_os, etc.)
│   ├── host.py             # Host platform interface
│   ├── log.py              # Logging configuration
│   │
│   ├── arch/               # Architecture implementations
│   │   ├── arch.py         #   QlArch — abstract base class
│   │   ├── x86.py          #   x86 / x86-64 / 8086
│   │   ├── arm.py          #   ARMv7 (32-bit)
│   │   ├── arm64.py        #   ARMv8 (64-bit)
│   │   ├── mips.py         #   MIPS32
│   │   ├── riscv.py        #   RISC-V 32-bit
│   │   ├── riscv64.py      #   RISC-V 64-bit
│   │   ├── ppc.py          #   PowerPC 32-bit
│   │   ├── cortex_m.py     #   ARM Cortex-M (MCU)
│   │   ├── register.py     #   Register management
│   │   └── models.py       #   CPU model definitions
│   │
│   ├── os/                 # Operating system implementations
│   │   ├── os.py           #   QlOs — abstract base class
│   │   ├── memory.py       #   QlMemoryManager
│   │   ├── fcall.py        #   Function call interface (read params, set return)
│   │   ├── mapper.py       #   Syscall/API mapping
│   │   ├── path.py         #   Virtual filesystem path resolution
│   │   ├── filestruct.py   #   File descriptor abstraction
│   │   ├── thread.py       #   Threading primitives
│   │   ├── posix/          #   POSIX shared layer (syscall handlers)
│   │   ├── linux/          #   Linux-specific OS
│   │   ├── freebsd/        #   FreeBSD-specific OS
│   │   ├── macos/          #   macOS-specific OS
│   │   ├── qnx/            #   QNX RTOS
│   │   ├── windows/        #   Windows (Win32/Win64 API emulation)
│   │   ├── uefi/           #   UEFI firmware services
│   │   ├── dos/            #   DOS (8086 interrupts)
│   │   ├── mcu/            #   Bare-metal microcontroller
│   │   └── blob/           #   Raw binary blob execution
│   │
│   ├── loader/             # Binary format loaders
│   │   ├── loader.py       #   QlLoader — abstract base class
│   │   ├── elf.py          #   ELF (Linux, FreeBSD, QNX)
│   │   ├── pe.py           #   PE (Windows)
│   │   ├── pe_uefi.py      #   PE for UEFI
│   │   ├── macho.py        #   Mach-O (macOS)
│   │   ├── dos.py          #   DOS COM/EXE
│   │   ├── mcu.py          #   MCU firmware images
│   │   └── blob.py         #   Raw binary blobs
│   │
│   ├── cc/                 # Calling conventions
│   │   ├── intel.py        #   cdecl, stdcall, ms64
│   │   ├── arm.py          #   aarch32, aarch64
│   │   ├── mips.py         #   MIPS o32
│   │   ├── riscv.py        #   RISC-V ABI
│   │   └── ppc.py          #   PowerPC ABI
│   │
│   ├── hw/                 # Hardware peripheral emulation (MCU)
│   │   ├── peripheral.py   #   Base peripheral class
│   │   ├── hw.py           #   Hardware manager
│   │   ├── gpio/           #   GPIO pins and interrupts
│   │   ├── timer/          #   Timers, PWM, counters
│   │   ├── char/           #   UART serial
│   │   ├── spi/            #   SPI bus
│   │   ├── i2c/            #   I2C bus
│   │   ├── net/            #   Network interfaces
│   │   ├── analog/         #   ADC/DAC
│   │   ├── intc/           #   Interrupt controllers
│   │   ├── flash/          #   Flash memory
│   │   ├── dma/            #   DMA controllers
│   │   └── ...             #   Power, SD, misc peripherals
│   │
│   ├── debugger/           # Debugger subsystem
│   │   ├── gdb/            #   GDB remote protocol server
│   │   └── qdb/            #   Qiling native debugger (with reverse debugging)
│   │
│   ├── extensions/         # Optional extensions
│   │   ├── multitask.py    #   gevent-based multithreading
│   │   ├── trace.py        #   Instruction tracing
│   │   ├── coverage/       #   Code coverage collection
│   │   ├── sanitizers/     #   Memory sanitizers
│   │   ├── afl/            #   AFL fuzzer integration
│   │   ├── r2/             #   Radare2 integration
│   │   └── idaplugin/      #   IDA Pro plugin
│   │
│   └── profiles/           # Default OS configuration files (.ql)
│       ├── linux.ql        #   Stack/heap addresses, kernel params
│       ├── windows.ql
│       ├── macos.ql
│       └── ...
│
├── qltool                  # CLI tool for running binaries
├── qltui.py                # TUI interface
├── examples/               # Usage examples and sample scripts
├── tests/                  # Test suite
└── docs/                   # Documentation
```

## Core Components

### `Qiling` (core.py)

The central class. Every emulation session creates one `Qiling` instance that owns and wires together all other components:

```python
ql = Qiling(
    argv=["/path/to/binary", "arg1"],   # binary + arguments
    rootfs="/path/to/rootfs",            # virtual filesystem root
    ostype=QL_OS.LINUX,                  # target OS (auto-detected if omitted)
    archtype=QL_ARCH.X8664,              # target arch (auto-detected if omitted)
)
```

`Qiling` inherits from `QlCoreHooks` (hook management) and `QlCoreStructs` (endian-aware packing). Key properties:

| Property | Type | Description |
|----------|------|-------------|
| `ql.arch` | `QlArch` | CPU architecture — registers, disassembly |
| `ql.os` | `QlOs` | Operating system — syscalls, I/O, APIs |
| `ql.loader` | `QlLoader` | Binary loader — parses and maps the executable |
| `ql.mem` | `QlMemoryManager` | Memory — map, read, write, MMIO |
| `ql.uc` | `unicorn.Uc` | Underlying Unicorn engine instance |

### Architecture Layer (`qiling/arch/`)

`QlArch` is the abstract base. Each architecture subclass configures:

- **Unicorn engine** mode and architecture constants
- **Register** access via `ql.arch.regs` (read/write by name)
- **Disassembler** (Capstone) and **assembler** (Keystone)
- **Stack operations** — push, pop, pointer-width-aware
- **Endianness** and **bit width** (16/32/64)

Supported: x86, x86-64, 8086, ARM, ARM64, MIPS, RISC-V (32/64), PowerPC, Cortex-M.

### OS Layer (`qiling/os/`)

`QlOs` is the abstract base. Each OS subclass provides:

- **Syscall/interrupt dispatch** — routes CPU interrupts to handler functions
- **I/O streams** — `stdin`, `stdout`, `stderr` (interceptable)
- **Virtual filesystem** — path mapping through `rootfs`
- **Function call interface** (`ql.os.fcall`) — read params, set return values
- **API interception** — `set_api()` for hooking library functions

**POSIX subsystem** (`os/posix/`): Shared syscall implementation for Linux, FreeBSD, macOS, and QNX. Individual syscall handlers live under `os/posix/syscall/`.

**Windows** (`os/windows/`): Emulates Win32/Win64 API by hooking DLL imports. Includes registry, thread, handle, and fiber support.

**UEFI** (`os/uefi/`): Emulates UEFI Boot Services, Runtime Services, and SMM. Uses a GUID database and protocol framework.

### Loader Layer (`qiling/loader/`)

`QlLoader` is the abstract base. Loaders parse a binary format, map segments into memory, resolve symbols, load dependencies, and set initial CPU state (PC, SP).

| Loader | Format | Used By |
|--------|--------|---------|
| `QlLoaderELF` | ELF | Linux, FreeBSD, QNX |
| `QlLoaderPE` | PE/COFF | Windows, UEFI |
| `QlLoaderMacho` | Mach-O | macOS |
| `QlLoaderDOS` | COM/EXE | DOS |
| `QlLoaderMCU` | Firmware | Cortex-M MCU |
| `QlLoaderBlob` | Raw bytes | Shellcode / blob |

### Memory Manager (`qiling/os/memory.py`)

Wraps Unicorn's memory model with higher-level operations:

- `map(addr, size, perms)` / `unmap(addr, size)` — region management
- `read(addr, size)` / `write(addr, data)` — data access
- `read_ptr(addr)` / `write_ptr(addr, val)` — pointer-width-aware access
- `read_cstring(addr)` — null-terminated string read
- MMIO callback support for memory-mapped peripherals

### Calling Conventions (`qiling/cc/`)

Each architecture has calling convention classes that abstract argument passing and return values. The `QlOs.fcall` interface uses these to provide a uniform way to read function parameters regardless of platform.

## Execution Flow

### 1. Initialization (`Qiling.__init__`)

```
Qiling(argv, rootfs)
  │
  ├─ Detect arch/OS from binary headers (ql_guess_emu_env)
  │    ELF magic → parse e_machine, OSABI
  │    PE magic  → parse Machine, Subsystem
  │    MachO magic → parse CPU type
  │
  ├─ Create QlArch (select_arch) → initializes Unicorn engine
  ├─ Create QlLoader (select_loader)
  ├─ Create QlMemoryManager
  ├─ Create QlOs (select_os)
  │
  └─ loader.run()
       ├─ Parse binary format (headers, segments, sections)
       ├─ Map segments into memory
       ├─ Load shared libraries / DLLs
       ├─ Setup stack, heap, TLS, auxiliary vectors
       └─ Set initial PC (entry point) and SP
```

### 2. Execution (`ql.run()`)

```
ql.run(begin, end, timeout, count)
  │
  ├─ Apply binary patches (ql.patch)
  ├─ Write exit trap (guard address)
  │
  └─ os.run()
       └─ uc.emu_start(entry_point, exit_point)
            │
            ├─ Unicorn executes instructions
            │
            ├─ Hooks fire on:
            │   ├─ Every instruction (hook_code)
            │   ├─ Basic blocks (hook_block)
            │   ├─ Memory access (hook_mem_read/write)
            │   ├─ Interrupts (hook_intno) → syscall dispatch
            │   ├─ Specific addresses (hook_address)
            │   └─ Specific instructions (hook_insn)
            │
            └─ Stops when PC reaches exit point, timeout,
               ql.emu_stop(), or unhandled exception
```

### 3. Syscall Handling

When the emulated binary issues a syscall (via `int 0x80`, `syscall`, `svc`, etc.):

```
CPU interrupt/instruction
  → Unicorn interrupt hook
    → QlOs syscall dispatcher
      → Look up handler by syscall number
        → Handler reads args via calling convention
          → Emulates syscall behavior
            → Sets return value in registers
```

## Component Selection

Components are selected dynamically at runtime based on `QL_ARCH` and `QL_OS` enums. The `qiling/utils.py` module provides:

- `select_arch(archtype)` → architecture class
- `select_os(ostype)` → OS class
- `select_loader(ostype)` → loader class
- `select_debugger(options)` → debugger class

This makes it possible to support diverse platform combinations from a unified codebase.

## Hook System

The hook system (`core_hooks.py`) wraps Unicorn's callback mechanism:

| Hook Type | Trigger |
|-----------|---------|
| `hook_code` | Every instruction (optionally within address range) |
| `hook_block` | Every basic block entry |
| `hook_address` | Specific address reached |
| `hook_intno` | CPU interrupt/exception |
| `hook_insn` | Specific instruction type (e.g., `syscall`) |
| `hook_mem_read` | Memory read |
| `hook_mem_write` | Memory write |
| `hook_mem_invalid` | Invalid memory access |

Hooks can be scoped to address ranges and return `QL_HOOK_BLOCK` to suppress further hooks in the chain.

## Key Extension Points

- **Custom syscall handlers** — replace or extend any syscall
- **API hooking** — `ql.os.set_api(name, callback)` to intercept library calls
- **Binary patching** — `ql.patch(offset, data)` for runtime patching
- **State snapshots** — `ql.save()` / `ql.restore()` for checkpointing
- **Debugger attachment** — GDB remote protocol or native QDB debugger
- **Coverage/tracing** — `extensions/coverage/` and `extensions/trace.py`
- **Fuzzing** — AFL integration via `extensions/afl/`
- **Hardware peripherals** — register custom MCU peripherals in `hw/`

## Dependencies

| Package | Role |
|---------|------|
| `unicorn` (2.1.3) | CPU emulation engine |
| `capstone` | Disassembly |
| `keystone-engine` | Assembly |
| `pyelftools` | ELF parsing |
| `pefile` | PE parsing |
| `python-registry` | Windows registry emulation |
| `gevent` | Cooperative multithreading |
| `pyyaml` | Configuration parsing |

Optional: `unicornafl` / `fuzzercorn` (fuzzing), `r2libr` (Radare2 integration).

## Supported Platforms

**Architectures:** x86, x86-64, 8086, ARM, ARM64, MIPS, RISC-V (32/64), PowerPC, Cortex-M

**Operating Systems:** Linux, FreeBSD, macOS, Windows, UEFI, DOS, QNX, MCU (bare-metal), Blob

## Improvement: Hybrid Kernel Architecture

> Detailed implementation plan and task tracking: [TODO.md](TODO.md)

### The Problem

Qiling reimplements Linux kernel behavior syscall-by-syscall in Python. This works
for simple operations (file I/O, memory management, stat) but fundamentally cannot
scale to the full kernel surface:

- **Networking**: No epoll. Sockets are proxied to host sockets with no isolation.
  No real TCP state machine, no multicast, no raw/netlink sockets.
- **Multithreading**: Gevent greenlets are cooperative and single-threaded. No
  preemption, no real concurrency. Futex is a gevent Event. Programs using pthreads,
  mutexes, or condition variables don't behave correctly.
- **Signals**: `signal()`, `sigaction()`, `kill()` are mostly stubbed. No delivery,
  no `EINTR`, no `SA_RESTART`.
- **Long tail**: capabilities, cgroups, namespaces, io_uring, seccomp, eBPF — the
  kernel API surface is vast and growing.

### The Solution

A **hybrid architecture** that keeps Unicorn for CPU emulation and Qiling for
instrumentation, but offloads complex kernel subsystems to a real Linux kernel via
a **kernel proxy** helper process. Simple syscalls stay emulated in Python.

```
Syscall interrupt
  → load_syscall() [UNCHANGED — existing dispatch in posix.py]
    → check posix_syscall_hooks[CALL]
      → proxy hook registered? → forward to kernel proxy
      → no proxy hook?         → existing Python handler [UNCHANGED]
```

The user explicitly chooses which missing syscalls to forward. Nothing is automatic —
by default Qiling behaves exactly as today. The integration uses the **existing
`set_syscall()` CALL hook mechanism** (`posix.py:128-143`), so `load_syscall()` and
all existing dispatch code remain completely unchanged.

```python
proxy = KernelProxy(ql)
proxy.forward_syscall("epoll_create", returns_fd=True)
proxy.forward_syscall("epoll_ctl")
proxy.forward_syscall("epoll_wait")
ql.run()
```

Under the hood, `forward_syscall()` registers a CALL hook that serializes the
arguments and sends them to a helper process (the kernel proxy) which executes
the real syscall and returns the result. For syscalls that return FDs, the result
is wrapped in a `ql_proxy_fd` object and stored in Qiling's FD table. Since the
FD table is already polymorphic (`ql_socket`, `ql_file`, `ql_pipe`), existing
handlers like `ql_syscall_read` and `ql_syscall_close` dispatch through the proxy
FD's `.read()`/`.close()` methods automatically — no changes needed.

### Phases

| Phase | Scope | Risk | Goal |
|-------|-------|------|------|
| 0 | Proof of concept | Low | User manually forwards specific syscalls — zero existing code changed |
| 1 | Networking foundation | Low-Med | Specific hooks for socket syscalls, `ql_proxy_fd`, TCP works |
| 2 | Complete networking | Medium | epoll, poll/select, network namespaces |
| 3 | Real threading | **High** | One Unicorn per thread, shared memory, real futex |
| 4 | Signals | Medium | Real signal delivery, EINTR, handler execution |
| 5 | Integration | Low | API polish, fallback, platform support, benchmarks |

Phase 0 gives users explicit control — they identify which missing syscalls to
forward and the proxy handles them. Phases 1-2 add pointer-aware forwarding for
networking with pre-built forwarders so users don't have to wire up each syscall.
Phase 3 (threading) is the highest-risk change and is deferred until networking is
stable. Each phase preserves backward compatibility — hybrid mode is opt-in, default
behavior is unchanged.

### Alternatives Considered

- **Run a real kernel in Unicorn**: Unicorn doesn't emulate hardware (interrupt
  controllers, MMU page tables, timers). Would require rebuilding QEMU system mode.
- **ptrace-based execution**: Run natively, intercept syscalls. Fast, but no
  cross-architecture support and limited instruction-level hooks.
- **User-Mode Linux (UML)**: Run the kernel as a userspace process. x86-only,
  somewhat unmaintained, complex syscall bridge.
- **Auto-forward all unimplemented syscalls**: Forward every missing syscall
  automatically. Convenient but unpredictable — hard to debug, may forward syscalls
  that shouldn't be (security, state leaks). Explicit user control is safer.

The hybrid approach was chosen because it preserves Qiling's core value
(instrumentation + cross-arch emulation) while getting real kernel behavior where
it matters most — without modifying the existing dispatch path.

## Testing

Tests live in `tests/` and are organized by platform: `test_elf.py`, `test_pe.py`, `test_macho.py`, `test_dos.py`, `test_mcu.py`, etc. They use binaries from `examples/rootfs/` as test fixtures.
