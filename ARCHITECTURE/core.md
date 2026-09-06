---
eatmycode_version: "1.1.0"
---

# Core — the Qiling facade and plumbing

## Goal

Own the public API and object lifecycle of an emulation: the `Qiling` class
composes arch, loader, memory, OS, and (bare-metal only) hardware components,
and exposes hooks, memory/register access, patching, save/restore, and the
component factories that resolve names to classes. It must not implement any
CPU, format, OS, or peripheral behavior itself. No roadmap milestone applies;
this is released infrastructure with maturity-based status.

## Status

`done` — exercised by every suite; the **How to Test** command boots
shellcode end-to-end through `Qiling.__init__` → `run()` → `emu_start`
(observed: `Ran 6 tests … OK`).

## Code Structure

| File | Role |
| ---- | ---- |
| `qiling/__init__.py` | Exports `Qiling`; `__version__` from package metadata |
| `qiling/core.py` | `Qiling`: constructor/composition root, `run`, `emu_start/stop`, `save/restore`, `patch`, properties, stop guard |
| `qiling/core_hooks.py` | `QlCoreHooks` mixin: wraps Unicorn hooks, dispatches to `Hook` lists, honors `QL_HOOK_BLOCK` |
| `qiling/core_hooks_types.py` | `Hook`, `HookAddr`, `HookIntr`, `HookRet` records |
| `qiling/core_struct.py` | `QlCoreStructs` mixin: endian/bit-width-aware `pack*/unpack*` helpers |
| `qiling/utils.py` | Name→class factories (`select_arch/loader/os/component/debugger`), binary sniffing, profile loading |
| `qiling/const.py` | Enums `QL_ARCH`, `QL_OS`, `QL_VERBOSE`, `QL_INTERCEPT`, `QL_STOP`, `QL_STATE`; groupings `QL_OS_POSIX`, `QL_OS_BAREMETAL`; hook flags |
| `qiling/exception.py` | `QlErrorBase` and its subclasses |
| `qiling/host.py` | `QlHost`: describes the *hosting* platform for pass-through decisions |
| `qiling/log.py` | Logger setup, colored/plain formatters, regex filter behind `Qiling.filter` |
| `qiling/profiles/*.ql` | Default per-OS INI profiles merged with user overrides |

## Language and Conventions

Python only; root toolchain and style rules apply (see
[ARCHITECTURE.md](../ARCHITECTURE.md#coding-style-and-code-design)). Local
patterns to follow:

- Circular-import avoidance with `TYPE_CHECKING` guards and string
  annotations (`qiling/core.py:1-33`, `qiling/log.py:15-19`).
- Components are reached through read-only properties (`mem`, `arch`,
  `loader`, `os`, `hw`, `log`; `qiling/core.py:203-244`); setters exist only
  for `verbose`, `debugger`, `filter`, `debug_stop`.
- Public hook methods are fully typed with callback `Protocol`s
  (`qiling/core_hooks.py:55-131`).
- Errors are `QlErrorBase` subclasses (`qiling/exception.py:9`); constructor
  failures raise `QlErrorFileNotFound`, `QlErrorArch`, `QlErrorOsType`
  (`qiling/core.py:104`, `:143-149`).

## Design and Invariants

- **Composition order is fixed** (`qiling/core.py:154-197`): arch →
  `QlCoreStructs`/`QlCoreHooks` init → logger → profile → loader → memory →
  OS → hw (bare-metal only) → `loader.run()` → stop guard. Later components
  read earlier ones during their own `__init__` (e.g. the OS reads
  `ql.profile` and `ql.mem`), so reordering breaks them.
- **Core never imports concrete subclasses.** All resolution goes through
  the dynamic-import factories in `qiling/utils.py` (`select_arch` `:376`,
  `select_loader` `:297`, `select_os` `:409`, `select_component` `:323`,
  `select_debugger` `:332`), which derive module and class names from the
  enum names. Adding an arch/OS means adding a module whose class name
  matches that derivation.
- **Hook dispatch protocol**: `QlCoreHooks` registers one Unicorn hook per
  type and fans out to Python `Hook` lists; a callback returning an int with
  `QL_HOOK_BLOCK` set (`qiling/const.py:77`) stops remaining hooks
  (`qiling/core_hooks.py:186`, `:209`). Address hooks are keyed per address
  (`hook_address`, `:550`). `begin=1, end=0` means "whole address space".
- **Exceptions raised inside hooks** are captured by the OS layer into
  `ql.internal_exception` and re-raised after `uc.emu_start` returns
  (`qiling/core.py:763`, `:773-774`), because Unicorn cannot propagate
  Python exceptions through its C callbacks.
- **Emulation state** is tracked in `QL_STATE` (`qiling/const.py:67`) around
  `emu_start` (`qiling/core.py:768-771`); `QlOs.call` refuses to move `pc`
  once stopped to work around a Unicorn bug (`qiling/os/os.py:215-221`).
- **Stop guard**: when `stop=QL_STOP.*` is requested, a trap page is mapped
  at or above `0x9000000` (`qiling/core.py:525`) and the loader's
  `skip_exit_check` decides whether the trap is written (`:546-558`).
- **Thumb workaround**: `emu_start` forces the low bit of `begin` when the
  arch was initialized in thumb mode (`qiling/core.py:759`); the FIXME there
  explains why this cannot live in the arch layer today.
- **Save/restore** snapshots are per-component dicts (`qiling/core.py:609`,
  `:658`); each component implements its own `save()/restore()`.

## Key Types and Entry Points

- `qiling/core.py:35` - `Qiling(QlCoreHooks, QlCoreStructs)` - facade;
  constructor kwargs at `:36-58` are the public construction contract
  (`argv`, `rootfs`, `env`, `code`, `ostype`, `archtype`, `cputype`,
  `verbose`, `profile`, `multithread`, `stop`, `endian`, `thumb`,
  `libcache`, …).
- `qiling/core.py:561` - `Qiling.run(begin, end, timeout, count)` -
  instantiates the debugger if configured, applies binary patches, writes
  the exit trap, calls `os.run()`, then `debugger.run()`.
- `qiling/core.py:743` - `Qiling.emu_start(begin, end, timeout, count)` -
  thin wrapper over `uc.emu_start`; manages thumb bit, `QL_STATE`, and
  exception re-raise.
- `qiling/core.py:609` / `:658` - `save()` / `restore()` - snapshot
  regs/mem/hw/fd/os/loader per component; optional pickle via `snapshot=`.
- `qiling/core.py:594` - `patch(offset, data, target=None)` - queue a binary
  or library patch applied by `do_bin_patch`/`do_lib_patch` (`:503`, `:509`).
- `qiling/core_hooks.py:150` - `QlCoreHooks` - `hook_code` (`:400`),
  `hook_block` (`:422`), `hook_address` (`:550`), `hook_intno` (`:575`),
  `hook_mem_read/write` (`:592`/`:610`), `hook_insn` (`:646`),
  `hook_del` (`:686`).
- `qiling/utils.py:278` - `ql_guess_emu_env(path)` - sniffs arch/OS/endian
  from path name, ELF, Mach-O, or PE headers when not given.
- `qiling/utils.py:419` - `profile_setup(ostype, user_config)` - YAML for
  MCU, else `ConfigParser` over `qiling/profiles/<os>.ql` plus user overrides
  (path or dict); `getint` accepts any base.
- `qiling/log.py:164` - `setup_logger(ql, logdevs, plain, override)` - builds
  the per-instance logger; `RegexFilter` (`:96`) implements `ql.filter`.

## Interactions

- Instantiates [arch.md](arch.md), [loader.md](loader.md),
  [os-base.md](os-base.md) (memory then OS), and [hw.md](hw.md) (bare-metal
  only) in the order above.
- Lazily instantiates [debugger.md](debugger.md) inside `run()` via
  `select_debugger`.
- [extensions.md](extensions.md), [cli.md](cli.md), and
  [kernel-proxy.md](kernel-proxy.md) consume only this public API.
- The OS layers register their syscall/API entry hooks through
  `QlCoreHooks` (`hook_intno`/`hook_insn`/`hook_code`/`hook_intr`, see
  [os-posix.md](os-posix.md), [os-windows.md](os-windows.md)).

## How to Test

```sh
cd tests && python3 test_shellcode.py   # pass = "Ran 6 tests … OK", exit 0
```

- Covers `Qiling(code=…)` construction and `run()` for x86/x86-64/ARM/
  ARM64/MIPS Linux shellcode (`tests/test_shellcode.py:90`).
- Hook semantics and save/restore are exercised indirectly by
  `tests/test_elf.py` and `tests/test_mcu.py` (`test_mcu_snapshot_stm32f411`,
  `tests/test_mcu.py:29`). There is no dedicated unit test for
  `QlCoreHooks`; see Open Gaps.

## Review and Refactor Guide

- **Adding a constructor option**: extend `Qiling.__init__`
  (`qiling/core.py:36`) and mirror it in `qiling/cli.py` if user-facing
  ([cli.md](cli.md)); keep the composition order intact.
- **Adding a hook type**: add the `Protocol`, the `hook_*` method, and a
  `_hook_*_cb` dispatcher in `qiling/core_hooks.py`, preserving
  `QL_HOOK_BLOCK` handling.
- **Adding an arch/OS/loader**: only the naming derivation in
  `qiling/utils.py` factories and the enums in `qiling/const.py` change here;
  the implementation belongs to the owning module.
- **Do not** import from `qiling/os`, `qiling/loader`, `qiling/arch` at
  module level in `qiling/core.py` beyond `TYPE_CHECKING`; the factories exist to
  keep that direction one-way.
- Improvement candidates (proposals, not accepted work): replace the
  `type()` checks in hook dispatch with `isinstance` and document return
  semantics (`qiling/core_hooks.py:186`, `:209`); replace the hard-coded
  guard-page floor `0x9000000` (`qiling/core.py:525`) with a profile value.
  Success check: existing suites stay green.

## Open Gaps / Roadmap

- No dedicated unit test for the hook engine or for `save/restore` outside
  MCU; coverage is indirect.
- The thumb workaround in `emu_start` (`qiling/core.py:759`) depends on
  Unicorn behavior; revisit only as part of a Unicorn upgrade (project-wide
  event, see the root deviations).
- `ChangeLog` stops at 1.4.6 (`ChangeLog:4`) while `pyproject.toml:4` is
  1.4.12.dev0.
- Feature wishlist lives in GitHub issue
  [#333](https://github.com/qilingframework/qiling/issues/333); the hybrid
  kernel roadmap is in `TODO.md` (owned by [kernel-proxy.md](kernel-proxy.md)).
