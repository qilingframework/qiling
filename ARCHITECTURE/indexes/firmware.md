---
eatmycode_version: "2.0.0"
---

# Firmware Routes

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: changing MCU/blob execution, peripheral scheduling or device models.

## Routes

| Source paths / task trigger | Responsibility | Read next |
| --- | --- | --- |
| `qiling/os/mcu/`, `qiling/os/blob/`, `qiling/extensions/multitask.py`, execution/count/timeout cases in `tests/test_mcu.py`, `test_blob.py`, `examples/src/blob/`; scheduling and raw execution | Bare-metal runtime | [Bare-metal](../modules/baremetal.md) |
| `qiling/hw/`, `qiling/extensions/mcu/`, register/device cases in `tests/test_mcu.py`, `examples/mcu/`; chip maps, MMIO, interrupts, external devices | Hardware models | [Hardware](../modules/hardware.md) |

`tests/test_mcu.py` has shared coverage: route instruction semantics to the
CPU owner and image/vector loading to loaders through the root runtime
branch. Timing and peripheral effects belong to the rows above.
`extensions/multitask.py` and `extensions/mcu/` are explicit exceptions to
general extensions ownership. UEFI services use the root operating-system branch.
