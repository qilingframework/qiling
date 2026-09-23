---
eatmycode_version: "2.1.0"
---

# Core Runtime

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: changing qiling/core*.py, utils.py, const.py, host.py, log.py, exception.py, __init__.py or profile composition.

## Responsibility and Status

Owns the public facade, component selection, hooks, packing, logging and
snapshot orchestration. **In progress:** runtime is implemented; sampled
execution passes, but hook lifecycle and complete state recovery are not
exhaustively verified. CPU execution and OS semantics belong to partners.

## Code Map

| Path / symbol | Role |
| --- | --- |
| [core.py](../../qiling/core.py): `Qiling` | Construction, run/stop, patch, save/restore and convenience APIs |
| [core_hooks.py](../../qiling/core_hooks.py): `QlCoreHooks`; `core_hooks_types.py` | Unicorn hook fan-out, callback contracts, handles/removal |
| [core_struct.py](../../qiling/core_struct.py): `QlCoreStructs` | Architecture-sized packing/unpacking |
| [utils.py](../../qiling/utils.py): `select_arch`, `profile_setup`; [profiles/](../../qiling/profiles/) | Dynamic component factories, detection, configuration merge |
| [const.py](../../qiling/const.py), [exception.py](../../qiling/exception.py), [log.py](../../qiling/log.py), [host.py](../../qiling/host.py), [__init__.py](../../qiling/__init__.py) | Enums, errors, logging, host detection, public import/version |
| [test_shellcode.py](../../tests/test_shellcode.py), [test_elf.py](../../tests/test_elf.py), [test_mcu.py](../../tests/test_mcu.py), [test_edl.py](../../tests/test_edl.py) | Lifecycle, hooks, patching and snapshots through real execution |

## Local Conventions

Use the [root baseline](../../ARCHITECTURE.md#code-conventions). Public facade
properties and hook callbacks are compatibility surfaces; preserve legacy
spellings. **Observed:** type hints coexist with wildcard imports; no local
formatter/type-checker override exists. Errors inside callbacks are stored
by `hookcallback` and re-raised by `emu_start`, not silently consumed.

## Contracts and Invariants

- Construction validates target/rootfs, selects architecture before packing
  and hooks, then creates profile/loader/memory/OS/hardware before
  `loader.run()`. Construction maps the image; callers can hook before `run()`.
- `run(begin,end,timeout,count)` configures OS execution, patches and stop
  guards. Timeout is microseconds at the core/Unicorn interface; MCU semantics
  differ. `stop()` delegates for multithread or bare-metal execution.
- Factories derive modules/class names from enums with explicit format/arch
  mappings. A new enum alone is insufficient (`utils.py`). Hook callback
  signatures and `QL_HOOK_BLOCK` behavior must survive dispatcher changes.
  Interrupt, memory-fault and invalid-instruction events that no hook
  handles raise `QlErrorCoreHook` (`core_hooks.py`); OS personalities
  choose which interrupt numbers they hook.
- Profiles use defaults plus OS/user overrides; MCU uses YAML-derived maps
  (`profile_setup`). Parsing belongs here; the consumer owns each key.
- `save` includes only selected components. `restore` applies only included
  keys; memory precedes registers/CPU-dependent state. Pickled snapshot files
  require trusted producers; component support varies (`core.py`).

## Dependencies and Boundaries

Read [arch](arch.md) when CPU/register contracts change, [OS base](os-base.md)
for memory/call contracts, [loaders](loaders.md) for construction/image state,
[bare-metal](baremetal.md) for scheduling, and [debugger](debugger.md) for
stop/attach behavior. Core composes implementations through factories. **Required:** do not add
module-level imports of concrete arch/OS/loader classes to core; use the
existing factories (annotation-only imports belong under `TYPE_CHECKING`).

**Preserved project dependency rule:** keep dependencies toward underlying
services; do not expand existing reverse edges incidentally. Source exceptions
are Cortex-M and MCU importing `extensions.multitask`, lazy r2 use in
`arch/utils.py`, and OS memory annotations in `arch/x86_utils.py`. Loaders
legitimately use OS structs/hooks, GDB uses Linux procfs, and CLI uses
coverage/report. This is a design constraint with documented exceptions,
not a claim that the tree is an acyclic import graph.

## Change Guide

| Change trigger | Inspect / extend | Required docs / checks |
| --- | --- | --- |
| Constructor/profile/factory option | Initialization ordering, defaults, enum maps, consumer | Update this owner and affected runtime owner; shellcode + consumer test |
| Hooks, patching, stop behavior | Dispatch/removal and internal exception propagation | Read debugger if resume changes; ELF hook and debugger regressions |
| Snapshot contents | Save/restore pairs for every changed component | Read affected state owners; ELF/MCU snapshot tests, trusted-input contract |

## Verification

From `tests/`, after root setup: `python -m unittest test_shellcode`;
`python -m unittest test_elf.ELFTest.test_memory_search` checks memory-facing
facade behavior. Both passed during the latest refresh on Linux/Python
3.13/Unicorn 2.1.3.
For snapshot changes use matching cases in `test_elf.py` and
`test_mcu.MCUTest.test_mcu_snapshot_stm32f411` (the MCU case also passed).
Fixtures are relative to `tests/`. Passing these does not certify every
hook kind, debugger combination or snapshot component.

## Known Gaps

`core.py:emu_start` retains a documented ARM Thumb workaround. Snapshot
completeness depends on each component's implementation; base OS state is
empty. A dedicated exhaustive hook lifecycle suite was not found. Broader
refactoring ideas in [TODO.md](../../TODO.md) are proposals, not implemented
behavior; keep changes scoped to an evidenced problem.
