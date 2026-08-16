# Core — the Qiling facade and plumbing

## Goal

Own the public API and object lifecycle of an emulation: the `Qiling` class
composes arch, loader, memory, OS, and (for bare-metal) hardware components,
and exposes hooks, memory/register access, patching, and save/restore to
users. No roadmap milestone applies — this is mature released infrastructure;
status is maturity-based per the control center.

## Status

`done` — exercised by the whole test suite; the How to Test command below
boots shellcode end-to-end through `Qiling.__init__` → `run()` → `emu_start`.

## Code Structure

| File | Role |
| ---- | ---- |
| `qiling/core.py` | `Qiling` class: constructor/composition root, `run`, `emu_start/stop`, `save/restore`, `patch`, properties |
| `qiling/core_hooks.py` | `QlCoreHooks` mixin: wraps Unicorn hooks, dispatches to `Hook` lists |
| `qiling/core_hooks_types.py` | `Hook`, `HookAddr`, `HookIntr`, `HookRet` records |
| `qiling/core_struct.py` | `QlCoreStructs` mixin: endian/bit-width-aware pack/unpack helpers |
| `qiling/utils.py` | Name→class resolution: `select_arch/loader/os/component/debugger`, binary format sniffing, profile loading |
| `qiling/const.py` | Enums: `QL_ARCH`, `QL_OS`, `QL_VERBOSE`, `QL_INTERCEPT`, `QL_STATE`, groupings `QL_OS_POSIX`/`QL_OS_BAREMETAL` |
| `qiling/exception.py` | `QlErrorBase` and ~20 subclasses (`QlErrorArch`, `QlSyscallError`, …) |
| `qiling/host.py` | `QlHost`: describes the *hosting* platform (for pass-through features) |
| `qiling/log.py` | Logger setup, colored/plain formatters, regex filtering behind `Qiling.filter` |
| `qiling/profiles/*.ql` | Default per-OS config (memory layout, kernel uid/gid/pid) merged with user overrides |

## Key Types and Entry Points

- `qiling/core.py:35` - `Qiling(QlCoreHooks, QlCoreStructs)` - the facade; `__init__` composes components in fixed order: arch (`:154`) → mixins (`:157`) → logger → profile (`:178`) → loader (`:183`) → memory (`:188`) → OS (`:189`) → hw if bare-metal (`:191`) → `loader.run()` (`:195`).
- `qiling/core.py:561` - `Qiling.run(begin, end, timeout, count)` - attaches debugger, applies patches, writes exit trap, delegates to `os.run()`.
- `qiling/core.py:743` - `Qiling.emu_start(begin, end, timeout, count)` - thin wrapper over `uc.emu_start`; manages thumb bit, `QL_STATE`, exception re-raise.
- `qiling/core.py:609` / `:658` - `save()` / `restore()` - snapshot regs/mem/fd/os per-component.
- `qiling/core_hooks.py:150` - `QlCoreHooks` - hook registration API: `hook_code` (`:400`), `hook_block` (`:422`), `hook_address` (`:550`), `hook_intno` (`:575`), `hook_mem_read/write` (`:592`/`:610`), `hook_insn` (`:646`), `hook_del` (`:686`).
- `qiling/utils.py:278` - `ql_guess_emu_env(path)` - sniffs arch/OS/endian from pathname, ELF, Mach-O, or PE headers when not given.
- `qiling/utils.py:297,376,409,323,332` - `select_loader/arch/os/component/debugger` - dynamic-import factories; core never imports concrete subclasses.
- `qiling/utils.py:419` - `profile_setup(ostype, user_config)` - YAML for MCU, else ConfigParser over `qiling/profiles/<os>.ql` + user overrides.

## Interactions

- Instantiates every other subsystem: [arch.md](arch.md), [loader.md](loader.md), [os-base.md](os-base.md) (memory + OS), [hw.md](hw.md) (bare-metal only).
- Lazily instantiates [debugger.md](debugger.md) inside `run()` via `select_debugger`.
- [extensions.md](extensions.md) and [cli.md](cli.md) consume only this public API.
- Hook dispatch protocol (`QL_HOOK_BLOCK`, `qiling/const.py:77`) is honored by the OS layers when they intercept syscalls/APIs.

## How to Test

```sh
cd tests && python3 test_shellcode.py   # pass = unittest "OK", exit code 0
```

- Exercises `Qiling(code=...)` construction and `run()` across x86/x86-64/ARM/ARM64/MIPS shellcode for Linux and Windows.

## Open Gaps / Roadmap

- `ChangeLog` lags the released version (1.4.6 vs 1.4.8 in `pyproject.toml`).
- `unicorn` is hard-pinned to 2.1.3; upgrading Unicorn is a project-wide event.
- Feature wishlist lives in GitHub issue [#333](https://github.com/qilingframework/qiling/issues/333).
