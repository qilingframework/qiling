---
eatmycode_version: "2.1.0"
---

# POSIX Personalities and Syscalls

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: changing qiling/os/posix/ except kernel_proxy/, or Linux, FreeBSD, macOS and QNX personalities.

## Responsibility and Status

Owns syscall ABIs/dispatch, common POSIX handlers, Linux processes/threads,
futex/procfs and FreeBSD/macOS/QNX personalities, including driver API
support. **In progress:** representative Linux, RISC-V and QNX execution
passes; full syscall, threading, network and macOS behavior is unverified.

## Code Map

| Path / symbol | Role |
| --- | --- |
| [posix/posix.py](../../qiling/os/posix/posix.py): `QlOsPosix`, `QlFileDes` | Hooks, argument dispatch, identity/network configuration and fd table |
| [posix/syscall/](../../qiling/os/posix/syscall/), [posix/syscall/abi/](../../qiling/os/posix/syscall/abi/) | Common handlers, syscall-register conventions and return encodings |
| [linux/linux.py](../../qiling/os/linux/linux.py): `QlOsLinux`; [linux/thread.py](../../qiling/os/linux/thread.py), [linux/futex.py](../../qiling/os/linux/futex.py), [linux/procfs.py](../../qiling/os/linux/procfs.py) | Linux traps, cooperative guest threads, futex state and virtual procfs |
| [freebsd/](../../qiling/os/freebsd/), [macos/](../../qiling/os/macos/), [qnx/](../../qiling/os/qnx/) | OS-specific maps, syscalls, structures, kernel APIs and messages |
| [test_posix.py](../../tests/test_posix.py), [test_elf.py](../../tests/test_elf.py), [test_elf_multithread.py](../../tests/test_elf_multithread.py), [tests/](../../tests/) `test_elf_ko.py`, `test_android.py`, `test_qnx.py`, `test_macho*.py`, `test_tendaac15_httpd.py` | Syscalls, programs, threads and platform integration |
| [examples/src/](../../examples/src/) `linux/`, `freebsd/`, `macos/`, `qnx/`; [profiles/](../../qiling/profiles/) | Guest fixture sources and consumed OS settings |

## Local Conventions

Use [root conventions](../../ARCHITECTURE.md#code-conventions). Common
handlers are `ql_syscall_<name>(ql, ...)`; ordinary positional parameter
names/counts matter because dispatcher introspection reads guest arguments.
OS-specific handlers precede common POSIX implementations. Keep per-OS
layouts and error semantics; do not unify superficially similar handlers.
Fixture Makefiles specify cross-compilers locally; no common C standard is declared.

## Contracts and Invariants

- Dispatch maps syscall ID to name, resolves CALL/ENTER/EXIT overrides by
  name or number, then OS-specific/common handler. ENTER may replace args;
  EXIT may replace result; `None` leaves the return register untouched
  (`QlOsPosix.load_syscall`). Missing handlers warn and raise only when
  `debug_stop` requests it; automatic host forwarding is absent.
- Syscall ABI owns register decoding and negative errno encoding. Function
  calling conventions are separate. Hook signatures must match dispatch
  introspection, particularly wrappers using only `*args`.
- Fds 0–2 track standard streams; descriptors are polymorphic objects.
  Closing/duplicating/replacing them must preserve ownership and errors.
- Linux guest threads use gevent/cooperative Unicorn contexts; this does
  not imply full native Linux scheduling or signal delivery. `sched.py`
  can call host fork; socket handlers operate on host sockets.
- Linux `/proc/self` mappings are installed only when not overridden.
  Profile identity and network keys affect observable guest behavior.
  macOS kernel and QNX message interfaces retain their own state/layouts.
- Linux registers `hook_intno` traps per architecture: the syscall
  interrupt (via `EXCP` enums on ARM/ARM64/MIPS, literals elsewhere) plus
  ARM/ARM64 `UDEF` and MIPS `RI` CPU exceptions.
  `hook_cpu_exception` logs the SIGILL equivalent and calls `ql.stop()`,
  so falling into non-code bytes ends emulation cleanly instead of raising
  `QlErrorCoreHook`; no guest signal handler runs (`linux/linux.py`).
- Syscall result structs follow `ql.arch.endian`: `statx` selects the
  `*EB` big-endian ctypes variants for EB guests (`syscall/stat.py`).
  Check endian handling in any handler that writes ctypes layouts.

## Dependencies and Boundaries

Read [OS base](os-base.md) for memory/paths/fds, [arch](arch.md) for syscall
register contracts, [loaders](loaders.md) for process entry/auxv/driver
imports, and [kernel proxy](kernel-proxy.md) for forwarded descriptors.
Proxy integration must use existing hooks and fd polymorphism; it does not
own dispatch. Filesystem/socket/fork operations expose host resources.

## Change Guide

| Change trigger | Inspect / extend | Required docs / checks |
| --- | --- | --- |
| New/fixed syscall | Mapping table, ABI, OS override/common handler | Update this contract; matching `test_posix`/ELF test and affected OS |
| Thread/futex/signal | Thread contexts, yielding, futex waiters | `test_elf_multithread.py`; mark unsupported semantics explicitly |
| CPU exception/trap | `hook_intno` registrations, `hook_cpu_exception`, `EXCP` enums | Shellcode illegal-instruction cases; read arch for new exception codes |
| FD/path/socket | Host object lifetime, errno, guest structure layouts | OS-base checks and syscall regression; proxy checks if shared operations change |
| macOS/QNX/kernel API | Local maps/structs, loader imports | Platform-specific test and loader owner |

## Verification

From `tests/`: `python -m unittest test_elf.ELFTest.test_elf_linux_x8664 test_riscv test_qnx`
and `python -m unittest test_shellcode.TestShellcode.test_linux_arm64_illegal_instruction test_shellcode.TestShellcode.test_linux_mips32_illegal_instruction test_elf.ELFTest.test_linux_statx_bigendian`
passed during the latest refresh. They check sample Linux/RISC-V/QNX flows,
SIGILL-style termination and big-endian `statx`, not every handler.
For POSIX changes run `python test_posix.py` (also imports ELF,
RISC-V and CLI suites), and the relevant thread/kernel/network/platform
script. Follow [shared test-resource rules](cli-build.md#verification) when
running these suites. Root Linux aggregate is the broader CI gate; its fixtures, extracted
kernel sample and network/host requirements apply. Full aggregate was not run.

## Known Gaps

macOS CI is commented out. Some thread classes are unset for RISC-V/PPC;
signal syscall state is not proof of full delivery. CPU-exception hooks
exist only for ARM/ARM64/MIPS; x86, RISC-V and PPC undefined instructions
still surface as `QlErrorCoreHook`. Existing kernel-module
archives need fixture preparation. `TODO.md` hybrid phases are plans; proxy
Phase 0 implementation is documented separately. Current representative
checks do not establish kernel fidelity or host isolation.
