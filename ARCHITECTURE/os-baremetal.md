# OS bare-metal — MCU firmware and raw blobs

## Goal

Execute code with no operating system. MCU mode runs microcontroller firmware
(STM32, GD32V, NXP, …) with peripheral emulation and interrupt scheduling on
a cooperative multitasking wrapper around Unicorn; BLOB mode runs raw binaries
(e.g. u-boot) at a fixed load address with no OS services at all. Mature
released infrastructure; maturity-based status.

## Status

`done` — MCU covered by `tests/test_mcu.py` (STM32F1/F4, GD32VF1 firmware),
BLOB by `test_blob.BlobTest.test_uboot_arm` and `tests/test_edl.py`. The other
case in `tests/test_blob.py` is blocked on a missing fixture (see Open Gaps).

## Code Structure

| File | Role |
| ---- | ---- |
| `qiling/os/mcu/mcu.py` | `QlOsMcu` run loop + `MCUTask` driving Unicorn and peripheral steps |
| `qiling/os/blob/blob.py` | `QlOsBlob`: minimal run loop for raw binaries |
| `qiling/extensions/multitask.py` | `UnicornTask` / `MultiTaskUnicorn`: cooperative multitasking over Unicorn |

## Key Types and Entry Points

- `qiling/os/mcu/mcu.py:41` - `QlOsMcu(QlOs)` - run loop; steps hardware between execution chunks and delivers interrupts.
- `qiling/os/mcu/mcu.py:17` - `MCUTask(UnicornTask)` - the firmware execution task.
- `qiling/extensions/multitask.py:26` / `:152` - `UnicornTask` / `MultiTaskUnicorn(Uc)` - task-switching Unicorn subclass MCU mode runs on.
- `qiling/os/blob/blob.py:14` - `QlOsBlob(QlOs)` - runs `entry_point` → `exit_point` with no OS services.
- MCU selection: `QL_OS.MCU` is the only member of `QL_OS_BAREMETAL` (`qiling/const.py:74`); `ql.baremetal` (`qiling/core.py:357`) gates hardware-manager creation.

## Interactions

- Both subclass [os-base.md](os-base.md) `QlOs`.
- MCU mode drives [hw.md](hw.md): `QlHwManager.step()` is called between execution slices; board/chip memory maps come from `qiling/extensions/mcu/` passed as `env=`.
- Interrupt entry/exit uses `QlInterruptContext` in [arch.md](arch.md) (`qiling/arch/cortex_m.py:25`).
- Firmware images are loaded by `QlLoaderMCU` / `QlLoaderBLOB` ([loader.md](loader.md)); MCU profiles are YAML (`profile_setup`, [core.md](core.md)).
- Fuzzing MCU firmware (e.g. `examples/fuzzing/stm32f429/`) combines this mode with [extensions.md](extensions.md) AFL support.

## How to Test

```sh
cd tests && python3 -m unittest test_blob.BlobTest.test_uboot_arm   # pass = "OK", exit 0
```

- MCU (also proves [hw.md](hw.md)): `cd tests && python3 test_mcu.py` — pass = `Ran 18 tests … OK`.
- Qualcomm EDL loader: `cd tests && python3 test_edl.py` — pass = `Ran 1 test … OK`.
- The whole `test_blob.py` file does **not** pass from a clean checkout; see
  Open Gaps.

## Open Gaps / Roadmap

- Supported chip families are those with board definitions in `qiling/extensions/mcu/` (STM32F1/F4, GD32VF1, NXP, Atmel, BES); new chips need new peripheral maps.
- BLOB mode provides no services by design — targets needing hardware must use MCU mode instead.
- `test_blob.BlobTest.test_blob_raw` (`tests/test_blob.py:85`) errors with
  `FileNotFoundError` on a clean checkout: it reads
  `examples/rootfs/blob/example_raw.bin` (`tests/test_blob.py:96`), but the
  pinned `examples/rootfs` submodule ships only `u-boot.bin.img`. Either the
  fixture must be added upstream and the submodule bumped, or the test skipped
  when the fixture is absent.
