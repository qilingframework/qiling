# HW — peripheral emulation for bare-metal targets

## Goal

Emulate memory-mapped peripherals (GPIO, UART/char, SPI, I2C, timers, DMA,
interrupt controllers, flash, …) so MCU firmware runs against realistic
hardware. Peripherals are instantiated from a YAML profile naming which
peripheral class sits at which MMIO base address. Only active in bare-metal
(MCU) mode. Mature released infrastructure; maturity-based status.

## Status

`done` — exercised by `tests/test_mcu.py` against STM32F1/F4 and GD32VF1
firmware images (UART echo, freertos, blink, crc, dma_clock, i2c/spi/lcd).

## Code Structure

| File | Role |
| ---- | ---- |
| `qiling/hw/hw.py` | `QlHwManager`: creates peripherals from profile, maps MMIO, steps them each tick |
| `qiling/hw/peripheral.py` | Base `QlPeripheral` (+ `QlPeripheralUtils`) |
| `qiling/hw/analog/ char/ dma/ flash/ gpio/ i2c/ intc/ math/ mem/ misc/ net/ power/ sd/ spi/ timer/` | One directory per peripheral class, chip-specific implementations inside |
| `qiling/hw/const/` | Register layout constants per chip family |
| `qiling/hw/connectivity.py`, `external_device/` | External-interface plumbing (e.g. connecting a fake device to a bus) |
| `qiling/extensions/mcu/` | Board/chip definitions (stm32f4xx, gd32vf1, nxp, atmel, bes): memory maps naming peripheral class + base address, passed as `env=` to `Qiling` |

## Key Types and Entry Points

- `qiling/hw/hw.py:14` - `QlHwManager` - available as `ql.hw`; created by core only when `ql.baremetal` (`qiling/core.py:191`).
- `qiling/hw/hw.py:23` - `QlHwManager.create(label, struct, base)` - instantiates a peripheral from the profile entry and maps its MMIO region.
- `qiling/hw/hw.py:82` - `QlHwManager.step()` - advances every peripheral one tick; called from the MCU run loop.
- `qiling/hw/peripheral.py:132` - `QlPeripheral(QlPeripheralUtils)` - base class: a ctypes register struct + read/write handlers on the MMIO region.
- `qiling/extensions/mcu/stm32f4xx/stm32f407.py` (and siblings) - chip `env` dicts consumed at `Qiling(..., env=...)` construction.

## Interactions

- Created by [core.md](core.md) for bare-metal targets; driven by the MCU run loop in [os-baremetal.md](os-baremetal.md) (`QlHwManager.step()` between execution slices).
- Interrupt controller peripherals (`intc/`) raise exceptions delivered through `QlInterruptContext` in [arch.md](arch.md).
- MMIO regions are mapped through `QlMemoryManager` ([os-base.md](os-base.md)).
- Profile parsing (YAML) is in `profile_setup` ([core.md](core.md), `qiling/utils.py:419`).

## How to Test

```sh
cd tests && python3 test_mcu.py   # pass = unittest "OK", exit 0
```

- Exercises GPIO, UART, EXTI, I2C, SPI, DMA, CRC, RTC, watchdog peripherals on real firmware from `examples/rootfs/mcu/`.

## Open Gaps / Roadmap

- Peripheral fidelity is demand-driven: registers behave as observed firmware needs, not per full datasheets.
- Chip coverage limited to families under `qiling/extensions/mcu/`; adding a chip means writing its memory map + any missing peripheral classes.
