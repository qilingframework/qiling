# OS POSIX — Linux, FreeBSD, macOS, QNX

## Goal

Emulate POSIX operating systems by intercepting syscalls: a shared
`QlOsPosix` layer owns the per-arch syscall ABI, number→name mapping, and the
file-descriptor table; per-OS subclasses add their personality (Linux futex
and procfs, macOS mach ports, QNX message passing). Mature released
infrastructure; maturity-based status.

## Status

`done` — Linux is the flagship target with the largest suite; FreeBSD/QNX
covered by dedicated tests; macOS tests are host-gated (see Open Gaps).

## Code Structure

| File | Role |
| ---- | ---- |
| `qiling/os/posix/posix.py` | `QlOsPosix`: syscall ABI per arch, dispatcher, `set_syscall`, fd table |
| `qiling/os/posix/syscall/` | Syscall implementations, one module per family (unistd, mman, socket, fcntl, signal, ioctl, …) |
| `qiling/os/posix/shm.py`, `msq.py` | SysV IPC (shared memory, message queues) |
| `qiling/os/linux/linux.py` | `QlOsLinux`: syscall hook wiring and the dynamic-ELF run loop |
| `qiling/os/linux/` | `futex.py`, `thread.py` (green threads), `procfs.py`, `map_syscall.py`/`syscall_nums.py`, `kernel_api/` (for .ko emulation) |
| `qiling/os/freebsd/freebsd.py` | `QlOsFreebsd` |
| `qiling/os/macos/macos.py` | `QlOsMacos` + mach ports/tasks/kext support |
| `qiling/os/qnx/qnx.py` | `QlOsQnx` + QNX message passing (`message.py`) |

## Key Types and Entry Points

- `qiling/os/posix/posix.py:48` - `QlOsPosix(QlOs)` - per-arch syscall ABI tables (`:69`), fd table, SysV IPC.
- `qiling/os/posix/posix.py:170` - `load_syscall()` - the dispatcher: syscall id → name (via per-OS `map_syscall`) → handler in `os/posix/syscall/*` or user override.
- `qiling/os/posix/posix.py:132` - `set_syscall(target, handler, intercept)` - user syscall hijack (by number or name, CALL/ENTER/EXIT).
- `qiling/os/posix/posix.py:100` - `__get_syscall_mapper(archtype)` - loads `qiling/os/<os>/map_syscall.py` dynamically.
- `qiling/os/linux/linux.py:26` - `QlOsLinux(QlOsPosix)` - `hook_syscall` (`:137`) registered on interrupt/insn hooks.
- `qiling/os/linux/linux.py:148` - `QlOsLinux.run()` - shellcode single-shot, gevent thread manager when `multithread=True`, or the common path: run ld.so to `elf_entry`, apply lib patches, then run to exit.

## Interactions

- Subclasses [os-base.md](os-base.md) `QlOs`; fd objects come from `qiling/os/filestruct.py`.
- Syscall entry is an arch hook: interrupt/insn hooks from [core.md](core.md) (`QlCoreHooks`) fire `hook_syscall`, using [arch.md](arch.md) registers per the syscall ABI.
- Runs binaries prepared by [loader.md](loader.md) (`QlLoaderELF`, `QlLoaderMACHO`).
- Path/fs access goes through `QlOsPath`/`QlFsMapper` in [os-base.md](os-base.md).
- Fuzzing harnesses in [extensions.md](extensions.md) commonly hijack fd 0 with `pipe.py` and syscalls via `set_syscall`.

## How to Test

```sh
cd tests && python3 test_posix.py   # pass = unittest "OK", exit 0
```

- Full POSIX coverage in CI: `tests/test_onlinux.sh` (adds `test_elf.py` targets, `test_elf_multithread.py`, `test_elf_ko.py`, `test_qnx.py`, `test_android.py`).

## Open Gaps / Roadmap

- macOS emulation tests (`test_macho.py`, `test_macho_kext.py`) need a macOS host with collected dylibs; the macOS CI job is commented out in `.github/workflows/build-ci.yml`.
- `test_elf_ko.py` requires a one-time `unzip -P infected m0hamed_rootkit.ko.zip` in `examples/rootfs/x86_linux/kernel/`.
- Syscall coverage is demand-driven — unimplemented syscalls raise/log and get added as targets need them.
