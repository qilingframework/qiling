# OS bare-metal — MCU firmware and raw blobs

## Goal

Execute code with no operating system. MCU mode runs microcontroller firmware
(STM32, GD32V, NXP, …) with peripheral emulation and interrupt scheduling on
a cooperative multitasking wrapper around Unicorn; BLOB mode runs raw binaries
(e.g. u-boot) at a fixed load address with no OS services at all. Mature
released infrastructure; maturity-based status.

## Status

`done` — MCU covered by `tests/test_mcu.py` (STM32F1/F4, GD32VF1 firmware),
BLOB by `tests/test_blob.py` (u-boot) and `tests/test_edl.py`.

## Code Structure

| File | Role |
| ---- | ---- |
| `qiling/os/mcu/mcu.py` | `QlOsMcu` run loop + `MCUTask` driving Unicorn and peripheral steps |
| `qiling/os/blob/blob.py` | `QlOsBlob`: minimal run loop for raw binaries |
| `qiling/extensions/multitask.py` | `UnicornTask` / `MultiTaskUnicorn`: cooperative multitasking over Unicorn |

## Key Types and Entry Points

- `qiling/os/mcu/mcu.py:37` - `QlOsMcu(QlOs)` - run loop; steps hardware between execution chunks and delivers interrupts.
- `qiling/os/mcu/mcu.py:17` - `MCUTask(UnicornTask)` - the firmware execution task.
- `qiling/extensions/multitask.py:26` / `:152` - `UnicornTask` / `MultiTaskUnicorn(Uc)` - task-switching Unicorn subclass MCU mode runs on.
- `qiling/os/blob/blob.py:12` - `QlOsBlob(QlOs)` - runs `entry_point` → `exit_point` with no OS services.
- MCU selection: `QL_OS.MCU` is the only member of `QL_OS_BAREMETAL` (`qiling/const.py:74`); `ql.baremetal` (`qiling/core.py:357`) gates hardware-manager creation.

## Interactions

- Both subclass [os-base.md](os-base.md) `QlOs`.
- MCU mode drives [hw.md](hw.md): `QlHwManager.step()` is called between execution slices; board/chip memory maps come from `qiling/extensions/mcu/` passed as `env=`.
- Interrupt entry/exit uses `QlInterruptContext` in [arch.md](arch.md) (`qiling/arch/cortex_m.py:25`).
- Firmware images are loaded by `QlLoaderMCU` / `QlLoaderBLOB` ([loader.md](loader.md)); MCU profiles are YAML (`profile_setup`, [core.md](core.md)).
- Fuzzing MCU firmware (e.g. `examples/fuzzing/stm32f429/`) combines this mode with [extensions.md](extensions.md) AFL support.

## How to Test

```sh
cd tests && python3 test_blob.py   # pass = unittest "OK", exit 0
```

- MCU (also proves [hw.md](hw.md)): `cd tests && python3 test_mcu.py`.
- Qualcomm EDL loader: `cd tests && python3 test_edl.py`.

## Open Gaps / Roadmap

- Supported chip families are those with board definitions in `qiling/extensions/mcu/` (STM32F1/F4, GD32VF1, NXP, Atmel, BES); new chips need new peripheral maps.
- BLOB mode provides no services by design — targets needing hardware must use MCU mode instead.
