---
eatmycode_version: "2.0.0"
---

# Hardware Models and MMIO

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: changing qiling/hw/, qiling/extensions/mcu/, chip environment maps, peripheral registers or external devices.

## Responsibility and Status

Owns hardware entity creation, MMIO dispatch, peripheral register/state
models, interrupt controllers and external-device connections. **In progress:**
selected STM32 USART and snapshot tests pass; device coverage is partial,
not a cycle-accurate silicon model.

## Code Map

| Path / symbol | Role |
| --- | --- |
| [hw/hw.py](../../qiling/hw/hw.py): `QlHwManager`, `QlPripheralHandler` | Entity/region registry, lookup, MMIO fallback and step/save/restore |
| [hw/peripheral.py](../../qiling/hw/peripheral.py): `QlPeripheral`, `QlPeripheralUtils` | ctypes registers, raw access, monitoring and read/write interception |
| [hw/connectivity.py](../../qiling/hw/connectivity.py), [hw/external_device/](../../qiling/hw/external_device/) | Peripheral I/O connections and external device models |
| [hw/](../../qiling/hw/), [hw/const/](../../qiling/hw/const/) | Device-class implementations, register masks and controller behavior |
| [extensions/mcu/](../../qiling/extensions/mcu/) | Chip-specific env dictionaries consumed by loaders/hardware |
| [test_mcu.py](../../tests/test_mcu.py), [examples/mcu/](../../examples/mcu/) | Firmware-driven device and state checks |

## Local Conventions

Use the [root baseline](../../ARCHITECTURE.md#code-conventions).
Observed device classes mirror chip/peripheral names and nested `Type`
ctypes register layouts; masks live in `hw/const`. `create` resolves class
names through `qiling.hw` exports, so add new exports and env entries together.
Register tables are source code, not a documented generated artifact;
no common regeneration command is established. Preserve local register fidelity.

## Contracts and Invariants

- Env entries provide `type`, `base`, `size` and/or `struct`, `kwargs`.
  Loader creates memory/MMIO/core devices; hardware creation records
  entity-relative regions rebased to guest addresses (`hw.py`, `loader/mcu.py`).
- MMIO handler converts address to peripheral offset. Unclaimed regions
  use a little-endian backing bytearray; missing peripheral implementations
  log a warning. Neither behavior proves an unmodeled device works.
- Register layout, reset values, access width, write-one-to-clear effects
  and interrupt flags are device contracts. `raw_read/raw_write` use ctypes
  memory copies: validate changed offsets/widths against register storage
  before reaching host memory.
- `step()` calls devices with step methods. Ordering/frequency is inherited
  from the MCU run loop, not physical elapsed time. Save/restore must keep
  device state, mappings and callbacks coherent with CPU/memory snapshots.
- Monitoring honors ENTER/CALL/EXIT hooks; replacement/read return behavior
  differs from ordinary observation. Preserve hook identity/removal and
  side-effect order when extending register access.

## Dependencies and Boundaries

Read [bare-metal](baremetal.md) for scheduling, [arch](arch.md) for interrupt
entry/return, [loaders](loaders.md) for env initialization and [OS base](os-base.md)
for MMIO mapping. `extensions/mcu/` belongs here, not to optional analysis
extensions. External devices may expose host I/O; treat those resources
according to the concrete connection implementation.

## Change Guide

| Change trigger | Inspect / extend | Required docs / checks |
| --- | --- | --- |
| New peripheral/chip | Register struct, masks, exports, env shape | Device-specific firmware assertion; loader if env schema changes |
| MMIO/access hook | Offset/width bounds, fallback storage, side effects | Read OS base; register read/write and hook lifecycle evidence |
| Interrupt/timing/snapshot | Device step/state, controller and CPU | Read bare-metal/arch; MCU snapshot and relevant firmware test |

## Verification

From `tests/`: `python -m unittest test_mcu.MCUTest.test_mcu_snapshot_stm32f411 test_mcu.MCUTest.test_mcu_usart_input_stm32f411`
passed 2 cases with current STM32 fixtures. These exercise snapshot state
and UART input, not every register or device family. For broader changes
use `python test_mcu.py` and matching cases/examples; external devices need
their own environment. Inspect guest output/register assertions for real pass evidence.

## Known Gaps

`QlHwManager.find` performs linear device-region lookup (its source TODO
notes potential caching); no performance claim is made. Missing devices
may fall back to storage. A dedicated exhaustive peripheral suite and full
cycle timing model were not found; accepted scope remains demand-driven.
