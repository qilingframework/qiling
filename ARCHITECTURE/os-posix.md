---
eatmycode_version: "1.2.0"
---

# OS POSIX — Linux, FreeBSD, macOS, QNX

## Goal

Emulate POSIX operating systems by intercepting syscalls: a shared
`QlOsPosix` layer owns the per-arch syscall ABI, number→name mapping, the
dispatcher, the fd table, and SysV IPC; per-OS subclasses add their
personality (Linux futex/procfs/threads/kernel modules, macOS mach ports
and kexts, QNX message passing, FreeBSD). It must not own the kernel proxy
(see [kernel-proxy.md](kernel-proxy.md)). No roadmap milestone applies;
maturity-based status.

## Status

`done` — Linux is the flagship target with the largest suite (observed:
`tests/test_posix.py` → `Ran 65 tests … OK (skipped=2)`); FreeBSD, QNX, and
Android are covered on Linux hosts; macOS suites are host-gated (see Open
Gaps).

## Code Structure

| File | Role |
| ---- | ---- |
| `qiling/os/posix/posix.py` | `QlOsPosix`: syscall ABI selection, dispatcher `load_syscall`, `set_syscall`, `QlFileDes` fd table, signals bitmap |
| `qiling/os/posix/syscall/abi/` | `QlSyscallABI` per arch (id/arg/return registers) |
| `qiling/os/posix/syscall/` | Syscall implementations, one module per family (`unistd`, `mman`, `socket`, `net`, `epoll`, `sched`, `futex`, `signal`, `ioctl`, …), re-exported by `__init__.py` |
| `qiling/os/posix/const.py`, `const_mapping.py`, `structs.py`, `stat.py` | Per-arch constants (incl. MIPS socket options), flag decoders, structs |
| `qiling/os/posix/shm.py`, `msq.py`, `filestruct.py` | SysV IPC and POSIX-specific fd objects (sockets, pipes) |
| `qiling/os/linux/linux.py` | `QlOsLinux`: syscall hook wiring per arch, procfs, dynamic-ELF run loop |
| `qiling/os/linux/thread.py`, `futex.py`, `procfs.py` | Green-thread manager per arch, futex emulation, `/proc` files |
| `qiling/os/linux/map_syscall.py`, `syscall_nums.py`, `syscall.py` | Number→name tables per arch, Linux-only syscalls |
| `qiling/os/linux/function_hook.py`, `fncc.py`, `kernel_api/` | ELF symbol hooking (`set_api` for user binaries) and `.ko` kernel API emulation |
| `qiling/os/freebsd/`, `qiling/os/macos/`, `qiling/os/qnx/` | `QlOsFreebsd`, `QlOsMacos` (+ mach ports/tasks/kext), `QlOsQnx` (+ `message.py`) |

## Language and Conventions

Python; root rules apply. Local patterns (enforced by the dispatcher, not a
linter):

- A syscall handler is a module-level function named
  `ql_syscall_<name>(ql, arg1, …)`; `SYSCALL_PREF`
  (`qiling/os/posix/posix.py:19`) is the prefix, and parameter names are
  read from the signature to log arguments (`:200-205`). Canonical example:
  `qiling/os/posix/syscall/sched.py:13` and `:133` (`clone`/`clone3`).
- Return an `int` (negative errno on failure) or `None` to leave the return
  register untouched (`qiling/os/posix/posix.py:227-229`).
- Constants are re-declared locally where the platform defines them
  (`qiling/os/posix/syscall/sched.py:14-39`); MIPS-specific socket values
  live in `qiling/os/posix/const.py:309-456`.
- Guest structs use `get_packed_struct` (`qiling/os/posix/syscall/epoll.py:35`).
- `qiling/os/posix/syscall/epoll.py:140-141` still contains tab-indented
  lines (the other such file is in [debugger.md](debugger.md)); do not add
  more.

## Design and Invariants

- **Entry**: `QlOsLinux.load` registers `hook_syscall` on the arch-specific
  trap (`hook_intno` for ARM/ARM64/MIPS/RISC-V/PPC, `hook_intno(0x80)` and
  `hook_insn(SYSCALL)` for x86, `qiling/os/linux/linux.py:53-116`).
- **Dispatch** (`load_syscall`, `qiling/os/posix/posix.py:170`): read id via
  the ABI (`get_id`, `qiling/os/posix/syscall/abi/__init__.py:31`) → map to
  name via `qiling/os/<os>/map_syscall.py` → look up user CALL hook, else
  `qiling/os/<os>/syscall`, else `qiling/os/posix/syscall` → run ENTER hook,
  handler, EXIT hook → set return value. Unknown syscalls log a warning and
  raise `QlErrorSyscallNotFound` only when `debug_stop` is set
  (`qiling/os/posix/posix.py:255-258`).
- **User overrides** go through `set_syscall(target, handler, intercept)`
  (`qiling/os/posix/posix.py:132`), keyed by name or number; `set_api` on
  non-driver binaries hooks ELF symbols via `FunctionHook` (`:149-153`,
  `qiling/os/linux/function_hook.py:499`).
- **fd table**: `QlFileDes` (`qiling/os/posix/posix.py:22`) is a
  fixed-size list of duck-typed
  objects (`ql_file`, sockets, pipes, `ql_proxy_fd`); handlers index it and
  call `read/write/close/fstat/…` without type checks.
- **Run loop** (`QlOsLinux.run`, `qiling/os/linux/linux.py:148`): shellcode
  runs once; `multithread=True` hands control to
  `QlLinuxThreadManagement` (`qiling/os/linux/thread.py:537`); otherwise
  run ld.so to `elf_entry`, apply lib patches, then run to the exit point.
- **Processes**: `clone` without `CLONE_VM` forks the host process
  (`qiling/os/posix/syscall/sched.py:50-59`); threads are gevent greenlets.
- **Networking** uses host sockets; the profile `[NETWORK]` section
  controls IPv6 and bind-to-localhost (`qiling/os/posix/posix.py:58-61`).

## Key Types and Entry Points

- `qiling/os/posix/posix.py:48` - `QlOsPosix(QlOs)` - ABI table (`:69-78`),
  fd table, IPC, signal bitmap.
- `qiling/os/posix/posix.py:170` - `load_syscall()` - the dispatcher.
- `qiling/os/posix/posix.py:132` - `set_syscall(target, handler, intercept)`.
- `qiling/os/posix/posix.py:100` - `__get_syscall_mapper(archtype)` - loads
  `qiling/os/<os>/map_syscall.py:get_syscall_mapper`.
- `qiling/os/posix/syscall/abi/__init__.py:14` - `QlSyscallABI` -
  `get_id` (`:31`), `get_params` (`:39`), `set_return_value` (`:53`).
- `qiling/os/linux/linux.py:26` - `QlOsLinux(QlOsPosix)` - `load` (`:53`),
  `setup_procfs` (`:123`), `hook_syscall` (`:137`), `run` (`:148`).
- `qiling/os/linux/map_syscall.py:14` - `get_syscall_mapper(archtype)` and
  the per-arch `*_syscall_table` dicts (also read by the kernel proxy).
- `qiling/os/freebsd/freebsd.py:16`, `qiling/os/macos/macos.py:24`,
  `qiling/os/qnx/qnx.py:23` - the other personalities.

## Interactions

- Subclasses [os-base.md](os-base.md) `QlOs`; fd objects come from
  `qiling/os/filestruct.py` and `qiling/os/posix/filestruct.py`.
- Syscall entry is an arch hook registered through [core.md](core.md)
  `QlCoreHooks`; registers are read through [arch.md](arch.md).
- Runs images prepared by [loader.md](loader.md) (`QlLoaderELF`,
  `QlLoaderMACHO`); kernel modules use `hook_kernel_api`
  (`qiling/os/linux/kernel_api/hook.py:14`).
- Path/fs access goes through `QlOsPath`/`QlFsMapper` ([os-base.md](os-base.md)).
- [kernel-proxy.md](kernel-proxy.md) plugs in purely through
  `set_syscall(…, QL_INTERCEPT.CALL)` and the fd table.
- Fuzzing harnesses in [extensions.md](extensions.md) hijack stdin with
  `qiling/extensions/pipe.py` and syscalls via `set_syscall`.
- [debugger.md](debugger.md) is attached by `Qiling.run` before `os.run()`.

## How to Test

```sh
cd tests && python3 test_posix.py   # pass = "Ran 65 tests … OK (skipped=2)", exit 0
```

- `tests/test_posix.py` aggregates `test_elf.py`, `test_riscv.py`, and
  `test_qltool.py`; the POSIX members the CI script `tests/test_onlinux.sh`
  adds are `test_elf_multithread.py` (`Ran 24 tests … OK (skipped=1)`,
  includes TCP/UDP/HTTP and `clone3`), `test_elf_ko.py`, `test_qnx.py`,
  `test_android.py`, `test_edl.py`, `test_tendaac15_httpd.py`. Run them
  one at a time (fixed localhost ports; see the root Verification and
  Review Map).
- `test_elf_ko.py` needs `unzip -P infected m0hamed_rootkit.ko.zip` in
  `examples/rootfs/x86_linux/kernel/` first (CI does this,
  `.github/workflows/build-ci.yml:73`); without it one case errors with
  `QlErrorFileNotFound`.
- macOS: `tests/test_macho.sh` on a macOS host with collected dylibs.

## Review and Refactor Guide

- **Adding a syscall**: implement `ql_syscall_<name>` in the matching
  `qiling/os/posix/syscall/<family>.py` (or `qiling/os/<os>/syscall.py` if
  OS-specific), ensure the name exists in every relevant
  `map_syscall.py` table, and add a case to `tests/test_elf.py` with a
  sample in the rootfs submodule. Coverage is demand-driven (root
  deviations); do not add unrequested syscalls.
- **ABI changes** touch `qiling/os/posix/syscall/abi/<arch>.py` only.
- **fd-table contract**: any new fd object must implement the `ql_file`
  method set used by `unistd.py`/`socket.py` handlers.
- **Do not** call host syscalls directly from handlers except through the
  existing fd objects; host forwarding is the kernel proxy's job.
- Improvement candidates (proposals): replace the bare `except:` in
  `qiling/os/posix/syscall/select.py:78` (`TODO.md:628-636`; the
  `filestruct.py` sites listed there are already fixed); un-skip
  `tests/test_elf.py:441` once the ARM sample is rebuilt. Success check:
  named tests pass without skips.

## Open Gaps / Roadmap

- macOS suites need a macOS host; the CI job is commented out
  (`.github/workflows/build-ci.yml:83-93`).
- Signals are largely stubs and threading is cooperative; `TODO.md:7-21`
  states the problem and `TODO.md:271-567` proposes phases 1–4 (networking,
  real threads, signals) on top of the kernel proxy.
- Two skipped tests: `tests/test_elf.py:441` (ARM sample) and `:887`
  (stdin hijacking); `tests/test_elf_multithread.py:185` (ARM big-endian
  invalid instruction).
