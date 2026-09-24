---
eatmycode_version: "2.1.0"
---

# Runtime Routes

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: changing facade composition, CPU behavior, image loading or shared profiles.

## Routes

| Source paths / task trigger | Responsibility | Read next |
| --- | --- | --- |
| `qiling/{__init__,core,core_hooks,core_hooks_types,core_struct,utils,const,exception,host,log}.py`, `qiling/profiles/`, hook/lifecycle cases in `tests/test_edl.py`; options, factories, hooks, snapshots, logging, profile merge | Facade and lifecycle | [Core](../modules/core.md) |
| `qiling/arch/`, `qiling/cc/`, `tests/test_cpu_models.py`, `test_riscv.py`, `test_shellcode.py`, `examples/shellcodes/`; register/CPU/ABI behavior | Architecture adapters | [CPU and ABI](../modules/arch.md) |
| `qiling/loader/`, image/entry/relocation cases in `tests/test_elf*.py`, `test_pe*.py`, `test_macho*.py`, `test_uefi.py`, `test_dos*.py`, `test_mcu.py`, `test_blob.py`; executable parsing | Image mapping | [Loaders](../modules/loaders.md) |

Shared tests route by the changed assertion: syscall/API behavior belongs
to the matching OS owner in the root Task Index, firmware timing/device
behavior to its firmware branch. Profile parsing is core; individual key
semantics belong to the consuming loader/OS. Example binaries use the same
behavior owners; fixture preparation belongs to CLI/build tooling.
