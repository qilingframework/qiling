---
eatmycode_version: "2.1.0"
---

# CPU Architecture and Calling Conventions

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: changing qiling/arch/, qiling/cc/, CPU models, register access, instruction mode or ABI slots.

## Responsibility and Status

Owns architecture adapters, the Unicorn instance, registers, assembler/
disassembler access and function calling conventions. **In progress:**
CPU-model, shellcode and RISC-V samples pass; this is not an exhaustive ISA
or cross-platform compatibility certification.

## Code Map

| Path / symbol | Role |
| --- | --- |
| [arch/arch.py](../../qiling/arch/arch.py): `QlArch` | CPU, pointer width, stack, context interface |
| [arch/register.py](../../qiling/arch/register.py): `QlRegisterManager` | Name-to-Unicorn registers and PC/SP aliases |
| [arch/](../../qiling/arch/), [arch/models.py](../../qiling/arch/models.py), `*_const.py` | Concrete x86/ARM/MIPS/RISC-V/PPC/Cortex-M adapters, CPU enums, register maps and `EXCP` exception codes |
| [cc/__init__.py](../../qiling/cc/__init__.py): `QlCC`, `QlCommonBaseCC` | Register/stack slots, result, return address, frame unwind |
| [arch/cortex_m.py](../../qiling/arch/cortex_m.py): `QlArchCORTEX_M` | Exception/vector state and task-aware Unicorn |
| [test_cpu_models.py](../../tests/test_cpu_models.py), [test_riscv.py](../../tests/test_riscv.py), [test_shellcode.py](../../tests/test_shellcode.py) | Model selection and instruction/ABI samples |

## Local Conventions

The [root baseline](../../ARCHITECTURE.md#code-conventions) applies. Adapter
names match `select_arch` class construction (`QlArch` + enum name);
`cc` intentionally retains public camelCase methods. Keep register maps,
CPU enums and architecture properties together. Python/native-engine
versions come from the root manifest, not individual adapters.

## Contracts and Invariants

- `pointersize = bits // 8`; stack operations use architecture-sized memory
  access and update SP only for push/pop. Register aliases must match GDB
  and saved context expectations (`arch.py`, `register.py`).
- Calling-convention argument **slots** need not equal argument indices:
  multiword arguments, shadow space, register exhaustion, stack return
  addresses and unwind rules differ (`cc/__init__.py`, `cc/intel.py`).
- Endianness, CPU mode and Thumb PC handling affect execution and instruction
  decoding. Preserve the ARM adapter's `effective_pc` (consumers fall back
  to `arch_pc` via `getattr`) and Cortex-M exception return behavior when
  changing ARM mode; inspect the core Thumb workaround too.
- Interrupt numbers delivered to `hook_intno` are QEMU exception codes.
  **Observed:** ARM/ARM64 and MIPS Linux traps use the `EXCP` enums in
  `cortex_m_const.py` and `mips_const.py`; x86/RISC-V/PPC still pass
  literals. Prefer an existing enum and extend it for new codes.
- Concrete adapters instantiate engine/assembler/disassembler objects;
  supported enums do not imply support for every OS/CPU combination.
  Cortex-M uses `MultiTaskUnicorn` and hardware interrupt state.
- CPU behavior belongs here; OS-specific selector/TLS policy belongs in the
  OS personality even when architecture helpers implement the mechanism.

## Dependencies and Boundaries

Read [core](core.md) for factory changes, [OS base](os-base.md) for fcall
marshalling, [POSIX](posix.md) for syscall ABIs (separate from function ABIs),
[debugger](debugger.md) for register wire order/step behavior, and
[bare-metal](baremetal.md)/[hardware](hardware.md) for Cortex-M interrupts.
Guest integers and host ctypes layouts must retain target width/endian;
never substitute host pointer size for a guest ABI.

## Change Guide

| Change trigger | Inspect / extend | Required docs / checks |
| --- | --- | --- |
| New arch/model | Concrete adapter, model enum, core selection | Update core routes/support claims; CPU-model + instruction test |
| Register/mode change | Maps, PC/SP, save/restore, disassembly | Read debugger; shellcode and relevant target regression |
| Function ABI | Slot width, return register/address, unwind | Read OS base plus API consumer; execute target function test |
| Cortex-M exception | Vector state, task/context switching | Read firmware partners; MCU snapshot/interrupt checks |

## Verification

From `tests/`: `python -m unittest test_cpu_models test_riscv test_shellcode`
with root dependencies and relevant rootfs samples. All selected modules
passed during the latest refresh (11 CPU-model/RISC-V and 8 shellcode
cases). Their scope is selected models/instructions and guest execution,
not instruction-set conformance.
For PPC changes use `test_elf.ELFTest.test_elf_linux_powerpc`; for ABI changes
run the consuming OS API/syscall regression as well.

## Known Gaps

There is no independent exhaustive calling-convention suite. RISC-V/PPC
Linux thread classes are unset in `qiling/os/linux/linux.py`; do not infer
thread support from CPU execution. Native engine upgrades need root-level
compatibility review and representative architecture tests.
