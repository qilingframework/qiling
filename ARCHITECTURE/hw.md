---
eatmycode_version: "1.2.0"
---

# HW — peripheral emulation for bare-metal targets

## Goal

Emulate memory-mapped peripherals (GPIO, UART/USART, SPI, I2C, timers,
DMA, interrupt controllers, flash, RTC, CRC, …) so MCU firmware runs
against realistic hardware. Peripherals are instantiated from the
chip `env` map naming which peripheral class sits at which MMIO base.
Owns the manager, the peripheral base classes, and every chip-specific
peripheral; the run loop belongs to [os-baremetal.md](os-baremetal.md).
No roadmap milestone applies; maturity-based status.

## Status

`done` — exercised by `tests/test_mcu.py` (observed: `Ran 18 tests … OK`)
across GPIO, USART, EXTI, I2C, SPI, DMA, CRC, ADC, watchdog, timers, and
NVIC on STM32F103/F407/F411/F429, GD32VF103, and SAM3X8E firmware.

## Code Structure

| File | Role |
| ---- | ---- |
| `qiling/hw/hw.py` | `QlHwManager` (`ql.hw`): creates peripherals from `env`, tracks MMIO regions, steps peripherals, save/restore; `QlPripheralHandler` MMIO bridge |
| `qiling/hw/peripheral.py` | `QlPeripheralUtils` (read/write hooks, `monitor` decorator) and base `QlPeripheral` (ctypes register struct, `raw_read/raw_write`, `region`) |
| `qiling/hw/connectivity.py` | `QlConnectivityPeripheral` + `PeripheralTube`: byte-stream peripherals (UART-like) with `send/recv` for tests |
| `qiling/hw/{analog,char,dma,flash,gpio,i2c,intc,math,mem,misc,net,power,sd,spi,timer}/` | One directory per peripheral class; chip-specific implementations inside (e.g. `qiling/hw/char/stm32f4xx_usart.py`, `qiling/hw/intc/cm_nvic.py`, `qiling/hw/timer/cm_systick.py`) |
| `qiling/hw/const/` | Register bit-field constants per chip family |
| `qiling/hw/external_device/` | External device models attached to buses |
| `qiling/extensions/mcu/{stm32f1,stm32f4,gd32vf1,nxp,atmel,bes}/` | Chip `env` dicts: entries typed `core`, `memory`, `mmio`, `peripheral` with `struct`, `base`, `kwargs` |

## Language and Conventions

Python; root rules apply. Local patterns (observed, enforced by
`QlHwManager.create`):

- A peripheral is a class whose inner `Type(ctypes.Structure)` lists
  registers in datasheet order with offset comments
  (`qiling/hw/char/stm32f4xx_usart.py:12-49`); `__init__(ql, label,
  **kwargs)` builds `self.instance` with reset values (`:51-58`).
- Register access overrides `read/write` decorated with
  `@QlPeripheral.monitor()` and falls back to `raw_read/raw_write`
  (`:60-70`, `qiling/hw/peripheral.py:157-173`).
- Class names are looked up by `struct` string through
  `ql_get_module_function('qiling.hw', struct)` (`qiling/hw/hw.py:81`), so
  every peripheral must be exported from `qiling/hw/__init__.py`.
- Bit-field constants live in `qiling/hw/const/<chip>_<periph>.py` as
  `IntEnum`-style classes.

## Design and Invariants

- **Creation**: `QlHwManager.create(label, struct, base, kwargs)`
  instantiates the class and records `region[label]` from
  `QlPeripheral.region` offset by `base` (`qiling/hw/hw.py:67-93`); an
  unknown `struct` logs a warning and returns `None` (FIXME at `:95`).
- **MMIO**: the loader calls `setup_mmio(begin, size, info)`
  (`qiling/loader/mcu.py:127`), which maps a `QlPripheralHandler` through
  `QlMemoryManager.map_mmio` (`qiling/hw/hw.py:143-146`); reads/writes are
  routed to `find(address)` and the peripheral's `read/write`
  (`:37-58`, `:124-133`).
- **Stepping**: `QlHwManager.step()` (`qiling/hw/hw.py:135-140`) calls
  `step()` on every peripheral that defines it, e.g.
  `qiling/hw/timer/cm_systick.py:29`; the MCU run loop invokes it once per
  instruction in step mode.
- **Interrupts**: NVIC peripherals hold `arch.interrupt_handler` and raise
  pending IRQs into the CPU (`qiling/hw/intc/cm_nvic.py:55`, `:127`).
- **User hooks**: `hook_read/hook_write` with `QL_INTERCEPT` stages
  (`qiling/hw/peripheral.py:34-46`); `watch()` enables verbose access logs.
- **Snapshots**: `QlHwManager.save/restore` (`qiling/hw/hw.py:165-171`)
  serialize each peripheral's ctypes register struct to bytes and back
  (`qiling/hw/peripheral.py:258-262`); `QlPripheralHandler.__getstate__`
  (`qiling/hw/hw.py:24`) strips the manager reference so the MMIO handler
  can be pickled with the memory map.
- Peripheral fidelity is demand-driven: registers behave as observed
  firmware needs, not per full datasheets (root deviations).

## Key Types and Entry Points

- `qiling/hw/hw.py:60` - `QlHwManager` - `create` (`:67`), `delete` (`:97`),
  `load_env` (`:107`), `load_all` (`:118`), `find` (`:124`), `step` (`:135`),
  `setup_mmio` (`:143`), `save/restore` (`:165`/`:171`); attribute access
  `ql.hw.usart1` via `__getattr__` (`:162`).
- `qiling/hw/hw.py:17` - `QlPripheralHandler` - `QlMmioHandler`
  implementation bridging MMIO to peripherals.
- `qiling/hw/peripheral.py:132` - `QlPeripheral(QlPeripheralUtils)` -
  `Type` struct, `raw_read/raw_write` (`:157`/`:163`), `read/write`
  (`:168`/`:172`), `region` (`:232`).
- `qiling/hw/peripheral.py:15` - `QlPeripheralUtils` - `hook_read/hook_write/
  hook_del` (`:34-50`), `monitor` (`:60`).
- `qiling/hw/connectivity.py:49` - `QlConnectivityPeripheral` -
  `send/recv` tubes used by tests to talk to UARTs.
- `qiling/extensions/mcu/stm32f4/stm32f407.py` (and siblings) - chip `env`
  passed as `Qiling(..., env=...)`.

## Interactions

- Created by [core.md](core.md) only when `ql.baremetal`
  (`qiling/core.py:191`); populated by the MCU loader
  ([loader.md](loader.md), `qiling/loader/mcu.py:110-131`).
- Driven by [os-baremetal.md](os-baremetal.md) `QlOsMcu.run` /
  `MCUTask.on_interrupted` via `step()`.
- Interrupt controllers call into [arch.md](arch.md) `QlArchCORTEX_M`.
- MMIO regions are mapped through `QlMemoryManager.map_mmio`
  ([os-base.md](os-base.md)).
- YAML profiles are parsed by `profile_setup` ([core.md](core.md)) and
  merged into `ql.env` by the loader.

## How to Test

```sh
cd tests && python3 test_mcu.py   # pass = "Ran 18 tests … OK", exit 0
```

- Firmware fixtures live in `examples/rootfs/mcu/{stm32f103,stm32f407,
  stm32f411,stm32f429,gd32vf103,sam3x8e}`.
- Each case asserts UART output or register state through
  `ql.hw.<label>` (`tests/test_mcu.py:57-76` for USART input).

## Review and Refactor Guide

- **New peripheral**: subclass `QlPeripheral` (or
  `QlConnectivityPeripheral` for byte streams), export it from
  `qiling/hw/__init__.py`, add constants under `qiling/hw/const/`, reference
  it from the chip `env`, and add a firmware-driven case to
  `tests/test_mcu.py`.
- **Register layout changes** must keep `Type` field offsets matching the
  datasheet; `field_description` (`qiling/hw/peripheral.py:182`) is used
  for logging only.
- **Do not** put run-loop or scheduling logic in peripherals; `step()` must
  be side-effect-bounded to one tick.
- Improvement candidate (proposal): cache `find(address)` lookups
  (TODO at `qiling/hw/hw.py:123`). Success check: `tests/test_mcu.py`
  runtime drops with unchanged results.

## Open Gaps / Roadmap

- Chip coverage limited to families under `qiling/extensions/mcu/`; adding
  a chip means writing its `env` map plus any missing peripheral classes.
- `QlHwManager.create` returns `None` for unknown peripherals instead of
  failing (FIXME at `qiling/hw/hw.py:95`).
- No unit tests target peripherals in isolation; all coverage is
  firmware-driven.
