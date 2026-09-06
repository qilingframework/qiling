# Arch — CPU architecture layer

## Goal

Own everything CPU-specific: the Unicorn `Uc` instance, register access, stack
primitives, disassembler/assembler, CPU models, and per-arch calling
conventions. This is the bottom layer — everything else reads `ql.arch`; arch
depends only on Unicorn/Capstone/Keystone. Mature released infrastructure;
maturity-based status.

## Status

`done` — all architectures exercised by the CI suite; CPU model selection
covered by `tests/test_cpu_models.py`.

## Code Structure

| File | Role |
| ---- | ---- |
| `qiling/arch/arch.py` | Abstract base `QlArch`: owns `uc`, `regs`, stack push/pop, save/restore, disassembler |
| `qiling/arch/x86.py` | `QlArchIntel` base + `QlArchA8086`/`QlArchX86`/`QlArchX8664`, GDT/MSR wiring |
| `qiling/arch/arm.py`, `arm64.py` | ARM/AArch64, thumb handling, coprocessor access |
| `qiling/arch/cortex_m.py` | Cortex-M on top of ARM: NVIC-style interrupt entry/exit for MCU mode |
| `qiling/arch/mips.py`, `riscv.py`, `riscv64.py`, `ppc.py` | Remaining architectures |
| `qiling/arch/register.py` | `QlRegisterManager` — attribute-style register read/write |
| `qiling/arch/models.py` | CPU model enums (`X86_CPU_MODEL` … `RISCV64_CPU_MODEL`) |
| `qiling/arch/msr.py`, `cpr.py`, `cpr64.py` | x86 MSRs, ARM/ARM64 coprocessor registers |
| `qiling/arch/utils.py` | `QlArchUtils`: disassembly output for verbose/trace modes |
| `qiling/cc/__init__.py` + `intel.py`, `arm.py`, `mips.py`, `ppc.py`, `riscv.py` | Calling conventions (arg/retval marshalling) consumed by `qiling/os/fcall.py` |

## Key Types and Entry Points

- `qiling/arch/arch.py:22` - `QlArch(ABC)` - cached properties `uc` (`:34`), `regs` (`:42`), `stack_push/stack_pop` (`:52`/`:66`), `save/restore` via UcContext (`:108`/`:112`), `disassembler` (`:117`).
- `qiling/arch/register.py:11` - `QlRegisterManager` - `ql.arch.regs.rax`-style access, backed by per-arch `*_const.py` tables.
- `qiling/arch/x86.py:22,53,79,111` - `QlArchIntel` / `QlArchA8086` / `QlArchX86` / `QlArchX8664`.
- `qiling/arch/cortex_m.py:67` - `QlArchCORTEX_M(QlArchARM)` - plus `QlInterruptContext` (`:25`) for exception entry/exit in MCU mode.
- `qiling/arch/models.py` - CPU model enums selected via the `cputype` kwarg (resolved in `select_arch`, `qiling/utils.py:376`).
- `qiling/cc/__init__.py:9` - `QlCC` - abstract calling convention; `QlCommonBaseCC` (`:110`); e.g. `qiling/cc/intel.py` defines `cdecl`/`stdcall`/`ms64`/`macosx64`.

## Interactions

- Instantiated first by [core.md](core.md) (`qiling/core.py:154`); `Qiling.uc` proxies `arch.uc` (`qiling/core.py:479`).
- [loader.md](loader.md) and the OS layers use `arch.regs` and stack primitives to set up entry state.
- `qiling/cc/` is consumed by `QlFunctionCall` in [os-base.md](os-base.md) for API argument marshalling.
- [debugger.md](debugger.md) reads/writes registers through this layer.

## How to Test

```sh
cd tests && python3 test_cpu_models.py   # pass = unittest "OK", exit code 0
```

- Broader arch coverage comes for free from `test_shellcode.py` (5 archs) and the per-OS suites.

## Open Gaps / Roadmap

- PowerPC and RISC-V have fewer OS-level tests than x86/ARM/MIPS (no dedicated POSIX suite beyond `tests/test_riscv.py`).
- Thumb state handling has a known fixup in `Qiling.emu_start` (`qiling/core.py:743`) rather than in the arch layer itself.
