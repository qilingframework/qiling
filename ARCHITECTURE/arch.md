---
eatmycode_version: "1.1.0"
---

# Arch — CPU architecture layer

## Goal

Own everything CPU-specific: the Unicorn `Uc` instance, register access,
stack primitives, disassembler/assembler, CPU models, and per-arch calling
conventions. This is the bottom layer: every other module reads `ql.arch`;
arch depends only on Unicorn/Capstone/Keystone (with the documented
exceptions below). No roadmap milestone applies; maturity-based status.

## Status

`done` — all ten architectures are exercised by the CI suites; CPU model
selection is covered by `tests/test_cpu_models.py` (observed:
`Ran 7 tests … OK`).

## Code Structure

| File | Role |
| ---- | ---- |
| `qiling/arch/arch.py` | Abstract base `QlArch`: owns `uc`, `regs`, stack push/pop, save/restore, disassembler/assembler |
| `qiling/arch/x86.py`, `x86_utils.py`, `x86_const.py`, `msr.py` | `QlArchIntel` base + `QlArchA8086`/`QlArchX86`/`QlArchX8664`; GDT/segment setup; MSRs |
| `qiling/arch/arm.py`, `arm_utils.py`, `arm_const.py`, `cpr.py` | ARM: thumb handling, coprocessor registers |
| `qiling/arch/arm64.py`, `arm64_const.py`, `cpr64.py` | AArch64 |
| `qiling/arch/cortex_m.py`, `cortex_m_const.py` | Cortex-M on top of ARM: `QlInterruptContext`, NVIC-style exception entry/exit for MCU mode; uses `MultiTaskUnicorn` |
| `qiling/arch/mips.py`, `riscv.py`, `riscv64.py`, `ppc.py` (+ `*_const.py`) | Remaining architectures |
| `qiling/arch/register.py` | `QlRegisterManager`: attribute-style register read/write |
| `qiling/arch/models.py` | CPU model enums (`X86_CPU_MODEL` … `RISCV64_CPU_MODEL`) |
| `qiling/arch/utils.py` | `QlArchUtils` (disassembly output for verbose modes) and the `assembler()` factory |
| `qiling/cc/__init__.py`, `intel.py`, `arm.py`, `mips.py`, `ppc.py`, `riscv.py` | Calling conventions (argument/return marshalling) consumed by `qiling/os/fcall.py` |

## Language and Conventions

Python; root rules apply. Local patterns:

- One class per architecture named `QlArch<ENUMNAME>` so `select_arch`
  can derive it (`qiling/utils.py:376-406`).
- Register tables live in `*_const.py` as name→Unicorn-constant maps and are
  handed to `QlRegisterManager` (`qiling/arch/register.py:16`).
- Calling conventions are small classes named after the ABI (`cdecl`,
  `stdcall`, `ms64`, `amd64`, `macosx64`, `aarch64`, `aarch32`, `mipso32`;
  `qiling/cc/intel.py:61-95`, `qiling/cc/arm.py:35-40`,
  `qiling/cc/mips.py:9`), all deriving from `QlCommonBaseCC`
  (`qiling/cc/__init__.py:110`).
- `TODO.md:638-644` records that GDT/segment validation in
  `qiling/arch/x86_utils.py` uses `assert`; treat that as observed, not a
  convention to copy.

## Design and Invariants

- `QlArch` creates the `Uc` lazily as a cached property (`qiling/arch/arch.py:34`)
  and exposes `regs` (`:42`), `stack_push/stack_pop` (`:52`/`:66`),
  `save/restore` via `UcContext` (`:108`/`:112`), `disassembler` (`:117`),
  and `assembler` (`:125`). Everything above arch must go through these.
- `ql.uc` is a proxy to `arch.uc` (`qiling/core.py:479`); there is exactly
  one Unicorn instance per `Qiling` (the multi-Unicorn threading idea in
  `TODO.md:462-488` is a proposal only).
- **Layering exceptions**: `qiling/arch/cortex_m.py:22` imports
  `MultiTaskUnicorn` from `qiling/extensions/multitask.py`;
  `qiling/arch/utils.py:94` lazily imports the r2 extension for symbol
  names; `qiling/arch/x86_utils.py:10` imports `QlMemoryManager` from OS
  base for the GDT manager's constructor annotation. Do not add further
  upward imports; see [os-baremetal.md](os-baremetal.md) for the multitask
  contract.
- CPU models are selected by the `cputype` kwarg and validated by
  `select_arch`; a model belongs to exactly one enum in
  `qiling/arch/models.py`.
- Endianness and thumb are constructor inputs for ARM/MIPS only
  (`qiling/utils.py:379-386`).

## Key Types and Entry Points

- `qiling/arch/arch.py:22` - `QlArch(ABC)` - base class; see properties
  above.
- `qiling/arch/register.py:11` - `QlRegisterManager` - `ql.arch.regs.rax`
  style access (`__getattr__` `:35`, `__setattr__` `:44`), plus
  `read/write` by name or Unicorn id (`:53`/`:62`).
- `qiling/arch/x86.py:22,53,79,111` - `QlArchIntel` / `QlArchA8086` /
  `QlArchX86` / `QlArchX8664`.
- `qiling/arch/cortex_m.py:67` - `QlArchCORTEX_M(QlArchARM)` -
  `interrupt_handler` (`:146`) consults `ql.hw.nvic` and enters the handler
  inside `QlInterruptContext` (`:25`).
- `qiling/arch/utils.py:106` - `assembler(arch, endianness, is_thumb)` -
  Keystone factory used by `qltool code --format asm`.
- `qiling/cc/__init__.py:9` - `QlCC` - abstract calling convention
  (`getRawParam`, `setReturnValue`, …); `QlCommonBaseCC` (`:110`).
- `qiling/utils.py:376` - `select_arch(archtype, cputype, endian, thumb)` -
  the only construction path (`qiling/core.py:154`).

## Interactions

- Constructed first by [core.md](core.md); `QlCoreStructs`/`QlCoreHooks`
  are initialized from `arch.endian`/`arch.bits`/`arch.uc`
  (`qiling/core.py:157-158`).
- [loader.md](loader.md) and the OS layers set initial register/stack state
  through `arch.regs` and the stack primitives.
- `qiling/cc/` is consumed by `QlFunctionCall` ([os-base.md](os-base.md))
  and by the Windows fcall selector (`qiling/os/windows/windows.py:41-65`).
- POSIX syscall ABIs are a separate table in
  `qiling/os/posix/syscall/abi/` ([os-posix.md](os-posix.md)), not here.
- [debugger.md](debugger.md) reads/writes registers through this layer and
  ships per-arch GDB target XML.
- [hw.md](hw.md) NVIC peripherals call `arch.interrupt_handler`
  (`qiling/hw/intc/cm_nvic.py:55`, `:127`).

## How to Test

```sh
cd tests && python3 test_cpu_models.py   # pass = "Ran 7 tests … OK", exit 0
```

- Broader coverage comes from `tests/test_shellcode.py` (five archs) and the
  per-OS suites; RISC-V has `tests/test_riscv.py` (`Ran 4 tests … OK`).
- There is no unit test for `qiling/cc/`; it is proven through Windows API
  calls (Windows host) and UEFI (`tests/test_uefi.py`).

## Review and Refactor Guide

- **New architecture**: add `qiling/arch/<name>.py` with `QlArch<ENUM>`,
  a `*_const.py` register table, a `qiling/cc/` convention, a
  `qiling/os/posix/syscall/abi/` ABI, a GDB XML directory, and the enum in
  `qiling/const.py:15`; then extend `select_arch`.
- **Register changes** affect `qiling/debugger/gdb/xml/<arch>/` and
  `qiling/debugger/qdb/arch/`; run `tests/test_debugger.py` and
  `tests/test_qdb.py`.
- **Do not** put OS-specific state (segment selectors for Windows, TLS) in
  arch classes; the OS layer owns that (`qiling/os/windows/windows.py:132`).
- Improvement candidate (proposal): move the thumb-bit fixup out of
  `Qiling.emu_start` (`qiling/core.py:759`) into `QlArchARM` once Unicorn
  reflects thumb mode in `cpsr` at init. Success check:
  `tests/test_shellcode.py::test_linux_arm_thumb` and `tests/test_qdb.py`
  stay green.

## Open Gaps / Roadmap

- PowerPC has no OS-level test suite beyond CPU model selection; RISC-V has
  four Linux tests.
- 8086 GDB stop replies use the wrong register names (FIXME at
  `qiling/debugger/gdb/gdb.py:242`).
- `TODO.md:655-657` notes the 32-bit GDT data segment is built with
  `QL_X86_A_PRIV_0` (`qiling/arch/x86_utils.py:167`); the 64-bit manager
  already uses ring 3 (`:200`, `:215`).
