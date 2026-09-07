---
eatmycode_version: "1.2.0"
---

# OS bare-metal — MCU firmware and raw blobs

## Goal

Execute code with no operating system. MCU mode runs microcontroller
firmware (STM32, GD32V, NXP, Atmel SAM, BES) with peripheral emulation and
interrupt delivery on a cooperative multitasking wrapper around Unicorn;
BLOB mode runs raw binaries (e.g. u-boot) at a fixed address with no OS
services. Owns the two run loops and the multitask Unicorn subclass; the
peripherals themselves belong to [hw.md](hw.md). No roadmap milestone
applies; maturity-based status.

## Status

`done` — MCU covered by `tests/test_mcu.py` (observed: `Ran 18 tests … OK`,
STM32F1/F4, GD32VF103, SAM3X8E firmware); BLOB by
`test_blob.BlobTest.test_uboot_arm` (`OK`). `tests/test_edl.py` is not
BLOB coverage: its ELF is sniffed as Linux and runs under `QlOsLinux`
([os-posix.md](os-posix.md)).
`test_blob.BlobTest.test_blob_raw` errors on the pinned rootfs submodule
(see Open Gaps).

## Code Structure

| File | Role |
| ---- | ---- |
| `qiling/os/mcu/mcu.py` | `QlOsMcu` run loop (step mode and fast mode) + `MCUTask` |
| `qiling/os/blob/blob.py` | `QlOsBlob`: minimal run loop for raw binaries |
| `qiling/extensions/multitask.py` | `UnicornTask`, `NestedCounter`, `MultiTaskUnicorn(Uc)`: cooperative multitasking over Unicorn |

## Language and Conventions

Python; root rules apply. `QlOsMcu`/`QlOsBlob` set `type = QL_OS.MCU|BLOB`
as class attributes (`qiling/os/mcu/mcu.py:42`) so `select_os` and
`ql.baremetal` work. Only MCU is in `QL_OS_BAREMETAL`
(`qiling/const.py:74`); BLOB is an OS without services but with a normal
memory manager.

## Design and Invariants

- **Step mode** (default): `QlOsMcu.run` loops `emu_start(pc, 0, count=1)`
  then `ql.hw.step()` until `exit_point`, `count`, or `stop()`
  (`qiling/os/mcu/mcu.py:74-90`); `timeout` is unsupported here.
- **Fast mode** (`ql.os.fast_mode = True`): a single `MCUTask` runs under
  `MultiTaskUnicorn.tasks_start` with a scheduling interval in ms
  (`qiling/extensions/multitask.py:154-158`); `count` means scheduling
  rounds, and `hw.step()` runs on interruption (`qiling/os/mcu/mcu.py:27-38`).
- **Interrupts**: NVIC peripherals call `arch.interrupt_handler`, which
  enters the vector inside `QlInterruptContext`
  (`qiling/arch/cortex_m.py:146-161`); the Unicorn exception hook is
  installed by the MCU loader (`qiling/loader/mcu.py:140`).
- **Effective PC**: run loops read `arch.effective_pc` when present to
  keep the thumb bit consistent (`qiling/os/mcu/mcu.py:54-58`).
- **BLOB**: `QlOsBlob.run` resolves entry/exit overrides, creates a heap
  only if the profile `[CODE]` section defines `heap_address`/`heap_size`,
  then runs `entry_point` → `exit_point` with the standard `emu_start`
  (`qiling/os/blob/blob.py:43-60`).
- `ql.hw` exists only when `ql.baremetal` (`qiling/core.py:191`,
  `:357`); BLOB targets needing hardware must use MCU mode.

## Key Types and Entry Points

- `qiling/os/mcu/mcu.py:41` - `QlOsMcu(QlOs)` - `run` (`:53`), `stop`
  (`:49`), `fast_mode` flag (`:47`).
- `qiling/os/mcu/mcu.py:17` - `MCUTask(UnicornTask)` - `on_start` (`:23`),
  `on_interrupted` (`:27`).
- `qiling/extensions/multitask.py:26` - `UnicornTask` - task record with
  `pc`; `:152` - `MultiTaskUnicorn(Uc)` - `task_create`, `tasks_start`.
- `qiling/os/blob/blob.py:14` - `QlOsBlob(QlOs)` - `run` (`:43`).
- `qiling/core.py:357` - `Qiling.baremetal` - gates hardware-manager
  creation.

## Interactions

- Both subclass [os-base.md](os-base.md) `QlOs`.
- MCU drives [hw.md](hw.md) through `ql.hw.step()`; peripherals and MMIO
  are created by the MCU loader ([loader.md](loader.md)) from the YAML
  profile and the `env` dict ([core.md](core.md) `profile_setup`,
  `qiling/utils.py:419`).
- Interrupt entry/exit uses [arch.md](arch.md) `QlArchCORTEX_M`; the
  Cortex-M arch constructs a `MultiTaskUnicorn` instead of a plain `Uc`
  (`qiling/arch/cortex_m.py:78`; the import at `:22` is one of the three
  documented upward imports in the arch layer, see [arch.md](arch.md)).
- Fuzzing MCU firmware (`examples/fuzzing/stm32f429/`) combines this mode
  with [extensions.md](extensions.md) AFL support.
- Snapshots include hardware state when `save(hw=True)`
  (`tests/test_mcu.py:29-56`).

## How to Test

```sh
cd tests && python3 -m unittest test_blob.BlobTest.test_uboot_arm   # pass = "OK", exit 0
```

- MCU (also proves [hw.md](hw.md)): `cd tests && python3 test_mcu.py`
  — pass = `Ran 18 tests … OK`.
- `python3 test_blob.py` as a whole fails on a clean checkout; see Open Gaps.

## Review and Refactor Guide

- **Run-loop changes** must keep step mode and fast mode behaviorally
  equivalent for `tests/test_mcu.py::test_mcu_hackme_stm32f429` and
  `::test_mcu_fastmode_stm32f429` (`tests/test_mcu.py:403`, `:427`).
- **New chip family**: add the `env` map under `qiling/extensions/mcu/`,
  any missing peripherals under `qiling/hw/` ([hw.md](hw.md)), a YAML
  profile if needed, and a firmware sample plus test case.
- **Do not** add OS services (syscalls, fs) to these run loops; that is a
  different OS personality.
- Improvement candidate (proposal): support `timeout` in step mode.
  Success check: a `tests/test_mcu.py` case with `timeout` set terminates.

## Open Gaps / Roadmap

- `test_blob.BlobTest.test_blob_raw` (`tests/test_blob.py:85`) reads
  `examples/rootfs/blob/example_raw.bin` (`:96`), which the pinned
  `examples/rootfs` submodule (`f71f45f`) does not ship; upstream `master`
  now contains it, so bumping the submodule should fix it (unverified
  locally).
- Chip coverage is limited to families under `qiling/extensions/mcu/`.
- BLOB provides no services by design.
