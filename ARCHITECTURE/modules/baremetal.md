---
eatmycode_version: "2.1.0"
---

# Bare-metal Execution

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: changing qiling/os/mcu/, qiling/os/blob/, qiling/extensions/multitask.py or firmware run/stop/count/timeout behavior.

## Responsibility and Status

Owns MCU/raw-BLOB run loops and the task-aware Unicorn scheduler used by
MCU emulation. **In progress:** MCU snapshot/USART and ARM U-Boot samples
pass; raw BLOB and complete fast-mode timing remain unverified. Peripheral
models and image mapping are separate owners.

## Code Map

| Path / symbol | Role |
| --- | --- |
| [mcu/mcu.py](../../qiling/os/mcu/mcu.py): `QlOsMcu`, `MCUTask` | Instruction stepping, fast mode and peripheral scheduling |
| [blob/blob.py](../../qiling/os/blob/blob.py): `QlOsBlob` | Raw code execution, function-call helpers and optional heap |
| [extensions/multitask.py](../../qiling/extensions/multitask.py): `MultiTaskUnicorn`, `UnicornTask` | Task contexts, stop/resume, gevent/native-engine coordination |
| [test_mcu.py](../../tests/test_mcu.py), [test_blob.py](../../tests/test_blob.py) | Firmware stepping, I/O, snapshots and raw code |
| [examples/src/blob/](../../examples/src/blob/), [examples/mcu/](../../examples/mcu/) | Raw fixture build and device/firmware examples |

## Local Conventions

Use [root conventions](../../ARCHITECTURE.md#code-conventions); preserve
legacy `runable` and task method spellings. `extensions/multitask.py` is
owned here despite its source prefix. Nonblocking task work yields through
gevent; don't block the cooperative loop with ordinary sleep. Raw fixture
Makefile uses `arm-none-eabi-*`, Cortex-A7/Thumb, freestanding/no standard
library flags; firmware builds are not part of the Python package build.

## Contracts and Invariants

- Normal MCU mode executes one instruction then `hw.step()`. `count` is
  instruction count; timeout is explicitly unsupported in this mode.
  `effective_pc` is used where available (`QlOsMcu.run`).
- Fast mode creates an `MCUTask`; `count` means scheduling rounds. Scheduler
  timeout code uses milliseconds (`MultiTaskUnicorn._timeout_main`), unlike
  core's microsecond API. Do not silently equate these units.
- `MCUTask.on_interrupted` advances peripherals on successful slices; CPU
  errors log and request stop instead of modeled HardFault delivery.
  Task locking serializes engine execution; it is not parallel guest CPU
  emulation. Preserve nested/context/stop behavior when changing scheduling.
- BLOB uses profile code/load/entry fields, optional profile heap and
  architecture-specific fcall. Default end is load address + code length;
  caller begin/end overrides affect execution (`QlOsBlob.run`).
- MCU and BLOB share a firmware-facing run boundary but have different
  timing/hardware semantics; BLOB does not automatically model peripherals.

## Dependencies and Boundaries

Read [hardware](hardware.md) for step/interrupt timing, [arch](arch.md) for
Cortex-M context/effective PC and [loaders](loaders.md) for env/vector/image
initialization. Read [core](core.md) for `stop`/count/timeout API changes;
[OS base](os-base.md) for BLOB heap/fcall. Do not move firmware scheduler
semantics into unrelated POSIX/Windows run loops.

## Change Guide

| Change trigger | Inspect / extend | Required docs / checks |
| --- | --- | --- |
| Step/count/timeout | Both normal and fast paths, task stop/error state | MCU test with explicit mode/units; hardware/arch partners |
| Snapshot/resume | CPU task context, memory and peripheral state | MCU snapshot regression; core/loaders if saved state changes |
| Raw code/heap | BLOB profile, entry/end, fixture build | U-Boot/raw BLOB case; OS-base/loader contract |

## Verification

From `tests/`: `python -m unittest test_mcu.MCUTest.test_mcu_snapshot_stm32f411 test_mcu.MCUTest.test_mcu_usart_input_stm32f411 test_blob.BlobTest.test_uboot_arm`
passed 3 cases during the latest refresh. Root dependencies and matching
STM32/U-Boot fixtures are required. Run `python test_mcu.py` for broader device/timing
changes and `python test_blob.py` for raw behavior; the full suites are not
certified by the selected cases.

## Known Gaps

`test_blob.BlobTest.test_blob_raw` fails because rootfs lacks
`blob/example_raw.bin`; [fixture source](../../examples/src/blob/Makefile)
exists but is not built or copied into the submodule; the case still
errors with a missing-file error.
Fast-mode faults currently stop cleanly instead of delivering hardware
HardFault. Timeout units differ by execution path; full scheduler timing
and MCU exception fidelity remain unverified.
