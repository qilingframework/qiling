---
eatmycode_version: "1.1.0"
---

# Qiling Framework — Architecture

This is the control center for agent-readable architecture docs.
Cross-cutting facts live here; each subsystem is documented once in
`ARCHITECTURE/<module>.md` (see the [Index](#index)). `CLAUDE.md` and
`AGENT.md` are symlinks to this file.

## Mission and Constraints

Qiling is a binary emulation framework: it emulates and sandboxes code in
an isolated environment across platforms and architectures. Built on
Unicorn Engine, it adds what raw CPU emulation lacks: operating-system
context (syscalls, APIs, filesystems, registries), executable-format
loading, and dynamic linking (`README.md:13-27`).

Supported combinations are defined in code:

- Architectures — `QL_ARCH` (`qiling/const.py:15`): 8086, x86, x86-64,
  ARM, ARM64, Cortex-M, MIPS, RISC-V 32/64, PowerPC.
- Operating systems — `QL_OS` (`qiling/const.py:28`): Linux, FreeBSD,
  macOS, Windows, UEFI, DOS, QNX, MCU (bare-metal), BLOB.
- Formats: ELF, PE, Mach-O, COM/EXE/MBR, Intel HEX / raw firmware; kernel
  modules for Windows `.sys`, Linux `.ko`, macOS `.kext`.

Observable behavior: `Qiling(argv, rootfs, …).run()` executes the target
with hooks at instruction, basic-block, memory, interrupt, syscall, and
API level; VM state save/restore; hot patching; GDB-server and built-in
Qdb debugging (with record/replay); AFL++ fuzzing; and an opt-in kernel
proxy that forwards chosen Linux syscalls to a real kernel.

Constraints and non-goals:

- Emulation is single-Unicorn, cooperative-thread; there is no preemptive
  threading, no signal delivery, and networking uses host sockets
  (`TODO.md:9-21`). Real threading and signals are proposals only.
- Windows and macOS emulation need host-collected, non-redistributable
  system libraries; those suites are host-gated.
- Coverage of syscalls, Win32 APIs, and peripheral registers is
  demand-driven; unrequested surface is out of scope (see deviations).
- `unicorn` is hard-pinned; upgrading it is a project-wide event.

## Languages and Toolchain

| Area | Language / tool | Evidence |
| ---- | --------------- | -------- |
| `qiling/`, `tests/`, `examples/*.py`, `qltool`, `qltui.py` | Python, declared `^3.10` | `pyproject.toml:37` |
| CI matrix | Python 3.11 and 3.13 on `windows-latest` and `ubuntu-latest` (four jobs); the ubuntu/3.13 job carries a `container: Docker` marker | `.github/workflows/build-ci.yml:13-18` |
| Packaging | Poetry 2 (`poetry-core>=2.0,<3.0`), version `1.4.12.dev0`, GPL-2.0-or-later; `qltool` console script | `pyproject.toml:4`, `:33-34`, `:61-63` |
| Wheel/sdist build check | `poetry check --lock`, `python -m build`, `twine check --strict` | `.github/workflows/pythonpublish.yml:20-44` |
| Container | `python:3.13-slim-trixie` multi-stage Poetry wheel build | `Dockerfile:1`, `:18-23` |
| Editor config | 4-space indent, LF, UTF-8, final newline for `*.py` | `.editorconfig:6-12` |
| Fixture sources | C/asm under `examples/src/`, `examples/shellcodes/`, `examples/fuzzing/*/fuzz.c` (built out-of-tree; binaries live in the rootfs submodule) | `examples/src/linux/hello.c` |
| Test scripts | Bash (`tests/test_onlinux.sh`, `tests/test_macho.sh`), batch (`tests/test_pe.bat`) | `tests/test_onlinux.sh:8-20` |

Runtime dependencies (`pyproject.toml:36-55`): `unicorn == 2.1.3`
(hard-pinned), `capstone ^5`, `keystone-engine ^0.9.2`, `pefile`,
`pyelftools`, `python-registry`, `gevent >=24.10`, `multiprocess`,
`pyyaml ^6`, `windows-curses` (Windows only), and the TUI trio
`python-fx`/`questionary`/`termcolor`. Extras: `fuzz` → `unicornafl`,
`fuzzercorn`; `RE` → `r2libr` (`pyproject.toml:57-59`).

No formatter, linter, or type checker is configured in the tree
(inspected: `pyproject.toml`, no `setup.cfg`/`tox.ini`/`.flake8`/
`.pre-commit-config.yaml`). Declared support is the `^3.10` range above;
the versions this refresh was verified with (Python 3.13.5, Poetry 2.1.2,
unicorn 2.1.3) are a local observation, not a repository constraint.

## System Design

Layers, bottom to top by import direction; a layer imports only layers
below it (plus the `Qiling` facade type from `qiling/core.py`, which every
module imports for annotations):

| Layer | Owner doc | Responsibility and state |
| ----- | --------- | ------------------------ |
| Arch | [arch.md](ARCHITECTURE/arch.md) | The single Unicorn instance, registers, stack, disassembler/assembler, calling conventions |
| Core | [core.md](ARCHITECTURE/core.md) | `Qiling` facade, composition order, hook engine, component factories, profiles, logging, exceptions |
| OS base | [os-base.md](ARCHITECTURE/os-base.md) | Memory manager/heap, fcall marshalling, rootfs-confined paths, fs mapper, fd objects, green-thread base |
| OS personalities | [os-posix.md](ARCHITECTURE/os-posix.md), [os-windows.md](ARCHITECTURE/os-windows.md), [os-baremetal.md](ARCHITECTURE/os-baremetal.md) | Syscall/API/interrupt dispatch and run loops; own guest process state |
| Loader | [loader.md](ARCHITECTURE/loader.md) | Parses the untrusted image, maps it, builds initial state, records image tables; imports the OS personality's structs, hooks, and API tables (`qiling/loader/elf.py:24-27`, `pe.py:22-26`) |
| Hardware | [hw.md](ARCHITECTURE/hw.md) | MMIO peripherals and chip maps for MCU mode |
| Optional | [debugger.md](ARCHITECTURE/debugger.md), [extensions.md](ARCHITECTURE/extensions.md), [kernel-proxy.md](ARCHITECTURE/kernel-proxy.md), [cli.md](ARCHITECTURE/cli.md) | Consume only the public `Qiling`/`QlOs` API |

Rules a change must respect:

- **Name-based composition.** Core resolves arch/loader/OS/component/
  debugger classes by deriving module and class names from enum names in
  `qiling/utils.py:297-417`; concrete classes are never imported by core.
- **Downward imports only.** Documented exceptions: `qiling/arch/cortex_m.py:22`
  and `qiling/os/mcu/mcu.py:11` import `qiling/extensions/multitask.py`,
  `qiling/arch/utils.py:94` lazily imports r2, `qiling/arch/x86_utils.py:10`
  imports `QlMemoryManager` from OS base for a type annotation, and
  `qiling/cli.py:22-23` imports coverage/report. Do not add more. Optional
  modules mostly use the public API but also reach into concrete types
  (`qiling/debugger/gdb/gdb.py:38`, `qiling/extensions/tracing/formats/registers.py:2`);
  that is downward and allowed.
- **Dispatch models.** POSIX intercepts syscalls by number
  (`qiling/os/posix/posix.py:170`); Windows/UEFI intercept API calls by
  IAT address (`qiling/os/windows/windows.py:172`); DOS intercepts
  interrupts by `(intno, AH)` (`qiling/os/dos/dos.py:83`); MCU steps
  instruction-by-instruction with peripherals (`qiling/os/mcu/mcu.py:53`).
- **User override protocol.** `set_syscall`/`set_api` with
  `QL_INTERCEPT.CALL|ENTER|EXIT` (`qiling/const.py:55`) is the only
  supported way to replace or wrap emulated behavior; the kernel proxy is
  built entirely on it.
- **Trust boundaries.** The guest is untrusted. Host exposure exists at:
  rootfs path resolution (`qiling/os/path.py:239`), loader parsing of
  header-derived sizes (`qiling/loader/`), host sockets and `os.fork` in
  POSIX (`qiling/os/posix/syscall/sched.py:52-60`), and explicitly
  forwarded syscalls in the kernel proxy.
- **Fidelity over abstraction.** Per-OS and per-chip code is deliberately
  repetitive to mirror real platform behavior (see deviations).

## Runtime and Data Flow

1. Entry: `qltool` (checkout) or the installed console script call
   `qiling.cli.run`, which ends in `Qiling(**ql_args)` (`qiling/cli.py:276`);
   library users construct `Qiling` directly.
2. `Qiling.__init__` (`qiling/core.py:35`) guesses arch/OS from the file if
   not given (`qiling/utils.py:278`), then composes in fixed order: arch →
   struct/hook mixins → logger → profile → loader → memory manager → OS →
   hardware manager (bare-metal only) → `loader.run()` → stop guard
   (`qiling/core.py:154-197`). The target is fully mapped when the
   constructor returns.
3. `Qiling.run()` (`qiling/core.py:561`) instantiates the debugger if set,
   applies queued patches, writes the exit trap, and delegates to
   `os.run()`; the debugger's `run()` follows.
4. The OS run loop drives `Qiling.emu_start` (`qiling/core.py:743`), the
   thin wrapper over `uc.emu_start` that manages the thumb bit, `QL_STATE`,
   and re-raises exceptions captured inside hooks.
5. Guest traps re-enter Python through `QlCoreHooks` dispatchers
   (`qiling/core_hooks.py:167-276`) into the OS layer's syscall/API
   handler, which reads arguments via the arch/ABI, executes, logs through
   `QlOsUtils.print_function`, records stats, and writes the return value.
6. Exit: the guest reaches the OS exit point or exit trap, `emu_stop` is
   called, `run()` returns; `ql.os.exit_code` carries the status. Unicorn
   errors surface as `UcError` after `QlOs.emu_error` dumps context
   (`qiling/os/os.py:249`).

Configuration contract: INI profiles per OS in `qiling/profiles/<os>.ql`
(sections such as `[OS32]/[OS64]`, `[CODE]`, `[KERNEL]`, `[MISC]`,
`[NETWORK]`; Windows adds `[PATH]`, `[USER]`, `[REGISTRY]`, …) merged with
a user path or dict (`qiling/utils.py:419-449`); MCU uses YAML merged into
`ql.env`. The `env` kwarg is the guest environment for POSIX/Windows and
the chip map for MCU.

Persistence: none by default. `Qiling.save/restore` snapshot per-component
state (optional pickle file); the Windows registry writes hives back at
run end; `QlPeCache` caches parsed DLLs when `libcache=True`.

Concurrency: one Unicorn per `Qiling`; POSIX/Windows threads are gevent
greenlets; MCU fast mode uses the cooperative `MultiTaskUnicorn`; `clone`
without `CLONE_VM` forks the host process; the kernel proxy is a child
process over a Unix socketpair.

## Workspace Map

| Path | Holds |
| ---- | ----- |
| `qiling/` | The framework package (owners in the Index) |
| `qiling/profiles/*.ql` | Default per-OS INI profiles |
| `qiling/os/posix/kernel_proxy/` | Kernel proxy (Linux-host optional feature) |
| `qiling/extensions/mcu/` | Chip `env` maps (owned by [hw.md](ARCHITECTURE/hw.md)) |
| `tests/` | Standalone `unittest` files run from `tests/`; CI drivers `test_onlinux.sh`, `test_pe.bat`, `test_macho.sh`; Qdb scripts in `qdb_scripts/`; scratch output in `log_test/` |
| `examples/` | Demo scripts, `fuzzing/`, `mcu/`, `shellcodes/`, `extensions/`, `scripts/` (DLL/dylib collectors), `src/` (fixture sources), and the `rootfs/` submodule (fixture binaries; do not edit in place, update the submodule) |
| `jexamples/` | Legacy examples, not covered by CI |
| `docs/` | One-line pointers to https://docs.qiling.io plus images; not a documentation source |
| `qltool`, `qiling/cli.py`, `qltui.py` | CLI launcher, implementation, TUI ([cli.md](ARCHITECTURE/cli.md)) |
| `pyproject.toml`, `poetry.lock` | The only manifest and lock file |
| `Dockerfile` | Container build of the wheel (build tooling; no runtime code) |
| `.github/workflows/` | `build-ci.yml` (tests), `pythonpublish.yml` (build checks + publish), `dockerimage.yml`, `giteesync.yml` |
| `TODO.md` | Hybrid-kernel design and the "Existing Issues" list; `ChangeLog` (stale at 1.4.6); `CREDITS.md`; `COPYING` |

Generated or vendored: `examples/rootfs/` (git submodule, regenerate with
`git submodule update --init`); `qiling/os/uefi/Uefi*.py`,
`PiMultiPhase.py`, `ProcessorBind.py` are EDK2-derived type tables (edit
with care, no generator in tree); `qiling/debugger/gdb/xml/` mirrors GDB's
target descriptions.

## Coding Style and Code Design

No enforced formatter/linter/type checker exists; the rules below are
observed conventions with canonical implementations.

- **Indentation**: 4 spaces (`.editorconfig:9-10`); 432 of 506 package
  files use it consistently. Two files still contain tab-indented lines
  (`qiling/os/posix/syscall/epoll.py:140-141`,
  `qiling/debugger/qdb/branch_predictor/__init__.py:13-17`); do not add
  more.
- **File header**: shebang plus the three-line framework banner
  (`qiling/core.py:1-4`).
- **Typing**: public APIs are annotated; circular imports are avoided with
  `from __future__ import annotations` and `TYPE_CHECKING` guards
  (`qiling/log.py:6`, `:17-19`; used in 42/49 modules respectively).
  Callback signatures are `Protocol`s (`qiling/core_hooks.py:55-131`).
- **Naming**: classes `Ql<Thing>`; enums `QL_*` (`qiling/const.py`);
  syscall handlers `ql_syscall_<name>` (`qiling/os/posix/posix.py:19`);
  Win32 hooks `hook_<Name>` with `@winsdkapi`
  (`qiling/os/windows/dlls/kernel32/fibersapi.py:14`); UEFI `@dxeapi`;
  peripherals `<Chip><Periph>` with an inner `Type` struct
  (`qiling/hw/char/stm32f4xx_usart.py:12`).
- **Errors**: raise `QlErrorBase` subclasses from `qiling/exception.py`;
  unknown syscalls/APIs log a warning and raise only under `debug_stop`
  (`qiling/os/posix/posix.py:255-258`, `qiling/os/windows/windows.py:195-198`).
  `TODO.md:628-644` lists bare `except:` sites and `assert`-based
  validation as known debt (18 bare `except:` remain in the tree today);
  do not add new ones.
- **Logging**: always `ql.log` (613 call sites); `print` is reserved for
  Qdb/TUI/IDA output. Syscall/API lines go through
  `QlOsUtils.print_function` (`qiling/os/utils.py:106`).
- **Guest structs**: `ctypes` via `qiling/os/struct.py` factories
  (`get_packed_struct`/`get_aligned_struct`) so endian/pointer width follow
  the target (`qiling/os/posix/syscall/epoll.py:31-45`).
- **Component resolution**: never import concrete arch/OS/loader classes
  in core; rely on the `select_*` factories (`qiling/utils.py:297-417`).
- **Tests**: one standalone `unittest` module per subsystem in `tests/`,
  run from that directory with relative rootfs paths
  (`tests/test_elf.py:120`); host-gated cases use `unittest.skipUnless`
  (`tests/test_kernel_proxy.py:17`, `tests/test_pathutils.py:31`).
- **Docstrings**: Google-style `Args:`/`Returns:` on public methods
  (`qiling/core.py:561-570`); comments explain workarounds with issue links
  (`qiling/os/os.py:215-221`).

## Verification and Review Map

Setup (Linux, from a clone with the submodule):

```sh
git submodule update --init            # examples/rootfs fixtures
python3 -m pip install -e .            # or: poetry install
cd examples/rootfs/x86_linux/kernel && unzip -P infected m0hamed_rootkit.ko.zip   # only for test_elf_ko.py
```

All test commands run from `tests/`; a pass is unittest `OK` and exit 0.

| Change area | Run | Owner doc |
| ----------- | --- | --------- |
| Core facade, hooks, factories | `python3 test_shellcode.py` | [core.md](ARCHITECTURE/core.md) |
| Arch/registers/CPU models | `python3 test_cpu_models.py`; `python3 test_riscv.py` | [arch.md](ARCHITECTURE/arch.md) |
| Loaders | `python3 -m unittest test_elf.ELFTest.test_elf_linux_x8664`; `python3 test_uefi.py`; `python3 test_dos.py`; `python3 test_mcu.py` | [loader.md](ARCHITECTURE/loader.md) |
| Memory/paths/structs | `python3 test_pathutils.py && python3 test_struct.py` | [os-base.md](ARCHITECTURE/os-base.md) |
| POSIX syscalls | `python3 test_posix.py` (adds `test_elf.py`, `test_riscv.py`, `test_qltool.py`); then `./test_onlinux.sh` for the CI set | [os-posix.md](ARCHITECTURE/os-posix.md) |
| Kernel proxy | `python3 test_kernel_proxy.py` (Linux host) | [kernel-proxy.md](ARCHITECTURE/kernel-proxy.md) |
| Windows/UEFI/DOS | `python3 test_uefi.py && python3 test_dos.py`; PE suites via `test_pe.bat` on Windows | [os-windows.md](ARCHITECTURE/os-windows.md) |
| MCU/BLOB run loops, peripherals | `python3 test_mcu.py`; `python3 -m unittest test_blob.BlobTest.test_uboot_arm`; `python3 test_edl.py` | [os-baremetal.md](ARCHITECTURE/os-baremetal.md), [hw.md](ARCHITECTURE/hw.md) |
| Debuggers | `python3 test_qdb.py`; `python3 test_debugger.py` | [debugger.md](ARCHITECTURE/debugger.md) |
| Extensions | `python3 test_history.py`; `python3 test_r2.py` with `[RE]` | [extensions.md](ARCHITECTURE/extensions.md) |
| CLI/packaging | `python3 test_qltool.py` (needs the package installed); `python -I tests/test_qltool.py InstalledQltool_Test -v` from the repo root against an installed wheel | [cli.md](ARCHITECTURE/cli.md) |

CI code checks: `build-ci.yml` runs `tests/test_onlinux.sh` on Ubuntu
(the container branch is dead code, see Roadmap) and
`tests/test_pe.bat` on Windows after `examples/scripts/dllscollector.bat`
(`.github/workflows/build-ci.yml:44-81`); `pythonpublish.yml` runs
`poetry check --lock`, `python -m build`, `twine check --strict`, and the
installed-wheel test on every push and pull request
(`.github/workflows/pythonpublish.yml:3`, `:20-44`).

Known failing or gated cases on a clean Linux checkout (evidence from
this refresh): `test_blob.BlobTest.test_blob_raw` (missing fixture in the
pinned submodule), `test_elf_ko.ELF_KO_Test.test_demigod_m0hamed_x86`
(needs the unzip step), `test_kernel_proxy…test_ptr_out_writes_back_to_guest_memory`
(test bug, see owner), and `InstalledQltool_Test` when the package is not
installed. Coverage gaps: no unit tests for the hook engine, memory
manager, heap, or calling conventions; Windows and macOS suites need
their hosts.

Review constraints beyond the shared checks: keep dependency direction
downward; keep guest-derived sizes bounded before host allocation; keep
`unicorn` pinned; new runtime dependencies are blockers (see deviations).

## Roadmap

Status: released project in maintenance (1.4.12.dev0). All modules are
`done` except the kernel proxy, which is `in progress (Phase 0)`.
Established implementation milestones exist only for the hybrid kernel
work in `TODO.md` (Phases 0–5, `TODO.md:81-622`); no other milestone IDs
are used in the tree.

Accepted coding work (evidence-backed, not yet done):

- Kernel proxy Phase 0 test fix (`tests/test_kernel_proxy.py:449-451`);
  Phases 1–5 remain designs (`TODO.md:271-622`).
- Bump `examples/rootfs` so `test_blob_raw` has its fixture
  ([os-baremetal.md](ARCHITECTURE/os-baremetal.md)).

Proposals (from `TODO.md:624-693`, each with an owner and check in the
module docs): remove bare `except:` blocks and `assert` validation; bound
`read_cstring`; structured `map_info` lookup; move the thumb fixup into
the arch layer; implement Windows/UEFI `save/restore`; hook-engine
`isinstance` cleanup; profile-driven guard page; un-skip the ARM and
wchar tests. Cross-cutting gaps: `ChangeLog` stops at 1.4.6
(`ChangeLog:4`); macOS CI is commented out
(`.github/workflows/build-ci.yml:83-93`); `jexamples/` is unexercised;
`build-ci.yml:77` reads `matrix.contrainer` (typo) so the Docker job
always takes the native branch. The feature wishlist is GitHub issue
[#333](https://github.com/qilingframework/qiling/issues/333).

## Development Loop

Coding Discipline governs writing; Review Checks govern review. This
loop connects them and defines when work is ready to release.

```text
Frame → Write → Prove → Review → Gate
          ▲          findings      │
          └────────────────────────┘
```

### The loop

**1. Frame.** Convert the request into a goal with an observable check.
Inspect the request, code, docs, and repository conventions; record the
narrowest supported assumptions. When using eatmycode, run its Version
and Freshness Gate before trusting architecture guidance. Ask one focused
question only when a required decision cannot be discovered or safely
inferred and guessing would materially change the result. Once framed,
continue without an approval pause.

**2. Write.** Make the smallest change that reaches the goal. Add no
unrequested features or abstractions, match local style, touch only
in-scope code, and remove only orphans created by the change.

**3. Prove.** Run relevant tests and retain observable evidence.

*Survey the suite before touching it.* Before adding, changing, merging,
or deleting any test, inventory the whole suite: enumerate every test
file and case name, then read in full each test whose subject, fixtures,
or assertions touch this change. Use a subagent for broad inventory when
supported. From that inventory decide the complete set of test edits at
once — what to change, what to add, what to merge, what to remove — each
backed by `file:line`, then execute only that plan. Never write a test
before the survey, and never discover existing coverage afterward.

The plan obeys four rules:

- **Reuse or extend first.** Add a case to the test that already owns
  the behavior or shares its setup, fixtures, and subject. A new test
  function or file is justified only when the survey found no existing
  test owning the behavior, or when merging would hide which case
  failed.
- **Add only what the goal needs.** A bug fix needs a reproducing
  regression test; a new capability needs a test of its claimed
  behavior. Nothing further.
- **Retire what this change made obsolete.** Delete tests whose behavior
  no longer exists, and merge tests this change turned into duplicates,
  citing the surviving test. Leave unrelated pre-existing tests alone;
  record suspected redundancy under **Open Gaps / Roadmap**.
- **Never delete to reach green.** A failing test is a finding for
  Write. Removal requires evidence that its behavior is gone or is still
  covered elsewhere, cited by `file:line`.

Coverage of claimed behavior must not decrease. A failure returns
directly to Write, never forward to Review.

**4. Review.** Walk all seven Review Checks as separate passes. Read
whole affected files, not only the diff. Every finding needs `file:line`
evidence. Use an independent agent or isolated pass for Fit,
Dependencies, and Security when available.

**5. Gate.** Apply the Definition of Done. Any unticked criterion,
`blocker`, or unresolved `major` returns its evidence to Write. All
criteria passing means the change is ready for public or production
release. There is no separate approval or reporting phase.

### Definition of Done

**Correctness**

- The framed goal and its named check pass.
- Tests cover claimed behavior and pass; a bug fix has a regression test.
- The suite was surveyed before any test was written, changed, or
  deleted; no added test duplicates coverage another test owns, and no
  removal left claimed behavior uncovered.
- The owning module's **How to Test** command passes with evidence.
- The project builds and tests from a fresh clone without local-only
  dependencies.

**Review**

- All seven Review Checks ran; none was skipped or assumed.
- No `blocker` or unresolved `major` remains.
- Nits were applied or consciously declined.

**Legibility and contract**

- An agent can locate the owning code, identify language/style/design
  constraints, select a safe change or refactor, review its impact, and
  run the right checks from `ARCHITECTURE.md` and the owning module docs.
- Every changed line serves the goal; no drive-by formatting, debugging
  remnants, commented-out code, secrets, tokens, or local paths remain.
- Public names, signatures, errors, and recovery are intelligible.
- Architecture docs and `file:line` references reflect current source;
  version stamps certify a verified contract migration, not just a
  metadata edit.
- Architecture docs contain only coding context; any encountered
  deployment guides or other non-coding material and obsolete links were
  removed from the doc set.
- Breaking changes, deprecations, dependencies, licenses, and attribution
  are handled; commit or PR text explains why.

### Iterating without thrashing

- Every pass closes a named finding and touches only what it names.
- Nits alone do not trigger another pass.
- Re-run Prove after every fix.
- Two no-change passes force Gate re-evaluation: release if Done passes;
  otherwise return the surviving evidence to Frame.
- Three passes on one finding return automatically to Frame for a new
  approach.
- Never widen scope to satisfy a finding. Record coding-related follow-up
  work under **Open Gaps / Roadmap**; keep non-coding work outside the
  architecture doc set.

## Coding Discipline

### 1. Think Before Coding

- Understand the request, code, goal, and repository conventions first.
- Record assumptions and choose the narrowest evidence-backed reading.
- Prefer the simpler approach when it reaches the same verified goal.
- Ask only during planning and only for a required answer that cannot be
  discovered or safely inferred.

### 2. Simplicity First

- Implement only what was requested.
- Do not add single-use abstractions, speculative flexibility, or checks
  for impossible conditions.
- If the implementation is materially larger than the problem, simplify
  it.

### 3. Surgical Changes

- Do not refactor, reformat, or clean up unrelated code.
- Match the surrounding style.
- Remove imports, variables, and functions made unused by this change;
  leave pre-existing dead code alone unless requested.
- Every changed line must trace to the stated goal.

### 4. Goal-Driven Execution

Turn work into verifiable outcomes, then loop until they pass:

- Add validation → invalid inputs are rejected by a named passing test.
- Fix a bug → a regression test fails before the fix and passes after.
- Refactor → behavior tests pass before and after.

Give every plan step its own check. Strengthen vague criteria from
repository evidence before implementation.

### Project-Specific Deviations

- Emulation fidelity beats abstraction: syscall, API, and peripheral
  implementations mirror the real platform's observable behavior even
  when that means repetitive per-OS or per-chip code. Cross-OS
  "unification" is a scope increase, not a simplification.
- Coverage is demand-driven by design (see the OS and HW module docs).
  Adding an unrequested syscall, Win32 API, or peripheral register is
  out of scope; record it under the owning module's **Open Gaps /
  Roadmap**.
- `unicorn` is hard-pinned (`pyproject.toml:39`). Changing it, or any
  behavior that depends on its version, is a project-wide event and
  never an incidental part of another change.
- The kernel proxy must integrate only through `set_syscall` and the fd
  table (`TODO.md:65-79`); changes to `load_syscall` or existing handlers
  on its behalf are out of scope.

## Review Checks

Run every check against every change before merge. Keep checks separate.

Four rules bind all checks:

- **Evidence or no finding.** Every finding cites `file:line`.
- **The repository is authoritative.** Demand only conventions visible
  in the tree.
- **Read files, not only hunks.** Context can invalidate a finding or
  reveal unreachable code, unused parameters, and hidden duplication.
- **Review the change, never the author.** Describe code and impact, not
  how or by whom it was produced.

### 1. Style

Check indentation and local file conventions. Mixed indentation is
`major`; a consistent new file using the wrong local indent is `nit`.
Leave machine-checkable formatting to existing formatters and linters;
never demand unrelated reformatting.

### 2. Naming

Compare new names with nearby precedents before filing a finding. If the
repository is inconsistent, demand nothing. A local mismatch is `nit`;
an inconsistent public name is `major`.

### 3. Duplication

Search distinctive constants, errors, fields, and call sequences—not
only symbol names—for code performing the same job. Cite both sites and
the remedy. Cross-layer duplication is `major`; small local repetition
is `nit`. Similar code with meaningfully different branches is not
duplication.

### 4. Quality

Require followable control flow, errors handled where they occur, and
abstractions proportional to the problem. Swallowed errors,
inappropriate prints, unexplained magic values, and dead branches are
`major`. Remove unrequested configurability, one-caller wrappers, filler
comments, debugging remnants, and unrelated formatting. Missing tests
belong to Prove, not this check.

### 5. Fit

Read `ARCHITECTURE.md` and the owning module doc before the diff. Check
documented language/toolchain constraints, code-design conventions,
scope, layering, ownership, invariants, public-API growth, compatibility,
and performance claims against source evidence. A layering violation or
unjustified public API is `major`. Architectural or public-behavior changes
must update the relevant docs in the same change.

### 6. Dependencies

Check manifests and imports, maintenance, supply-chain risk, advisories,
install-time behavior, license, transitive cost, and whether the standard
library is sufficient. An unjustified top-level dependency is `major`;
a live advisory or abandoned upstream is `blocker`. Incomplete evidence
does not pass.

### 7. Security

Check both defects and widened exposure: unsafe memory access, unchecked
sizes or offsets, integer overflow, path traversal, unsafe
deserialization, command construction, committed secrets, and unbounded
untrusted input. Trace input to impact; without a reachable path there is
no finding. A real defect is `major`; a trust-boundary break is `blocker`.
Describe the fix without publishing exploit steps.

### Severity and the merge threshold

| Severity | Effect |
| -------- | ------ |
| `blocker` | Must not merge. |
| `major` | Must be resolved before merge. |
| `nit` | Apply or consciously decline. |
| `info` | Context or a question; no action implied. |

Merge only with no `blocker` and no unresolved `major`. A check that did
not run does not pass. Findings feed Write and Gate directly; they do not
create a reporting phase.

### Project-Specific Deviations

- **Security, scope.** Qiling *emulates* untrusted binaries; guest code
  doing something hostile inside the sandbox is the product working, not
  a finding. Findings target the host boundary: rootfs escape via path
  handling (`qiling/os/path.py:239`), unchecked guest-controlled sizes or
  offsets reaching host allocations or `struct` unpacking, parser input in
  `qiling/loader/` reachable from an untrusted image, and syscalls
  forwarded to the host by the kernel proxy
  (`qiling/os/posix/kernel_proxy/__init__.py:237-265`).
- **Dependencies.** `pyproject.toml` is the only manifest. A new
  top-level runtime dependency is `blocker` absent an explicit request;
  optional integrations belong in an extra (`fuzz`, `RE`).
- **Style.** No formatter or linter runs in CI; the Style check enforces
  only `.editorconfig` (4-space indent, LF, final newline) and the local
  conventions in *Coding Style and Code Design*.

## Index

Reading path: run the freshness gate, read the sections above, pick the
owner below from the paths you are touching, then read that module doc
and its listed partners before the code.

| Module doc | Source paths | Responsibility | Read it when you… |
| ---------- | ------------ | -------------- | ------------------ |
| [core.md](ARCHITECTURE/core.md) | `qiling/core.py`, `core_hooks*.py`, `core_struct.py`, `utils.py`, `const.py`, `exception.py`, `log.py`, `host.py`, `profiles/` | `Qiling` facade, composition order, hook engine, component factories, profiles, logging | add a constructor option or hook type, register a new arch/OS/loader name, change save/restore or logging. Partners: every other module |
| [arch.md](ARCHITECTURE/arch.md) | `qiling/arch/`, `qiling/cc/` | CPU layer: Unicorn instance, registers, stack, disassembler, CPU models, calling conventions | add an architecture or CPU model, touch registers/thumb handling, change argument marshalling. Partners: os-base, debugger, os-posix (syscall ABI) |
| [loader.md](ARCHITECTURE/loader.md) | `qiling/loader/` | ELF, PE, PE/UEFI, Mach-O, DOS, MCU firmware, raw blob loading and initial state | change image parsing, entry/exit points, DLL/ld.so resolution, PE cache, MCU peripheral wiring. Partners: os-base, os-posix, os-windows, hw |
| [os-base.md](ARCHITECTURE/os-base.md) | `qiling/os/*.py` | Shared OS services: memory manager/heap, fcall, rootfs paths, fs mapper, fd objects, threads, stats, structs | change memory mapping, path virtualization, API-call protocol, stdio, struct helpers. Partners: all OS personalities, extensions |
| [os-posix.md](ARCHITECTURE/os-posix.md) | `qiling/os/posix/` (except `kernel_proxy/`), `qiling/os/linux/`, `freebsd/`, `macos/`, `qnx/` | Syscall dispatch, ABIs, syscall implementations, Linux threads/futex/procfs, kernel modules, macOS/QNX personalities | add or fix a syscall, change dispatch or fd handling, touch multithread emulation. Partners: os-base, arch, loader, kernel-proxy |
| [kernel-proxy.md](ARCHITECTURE/kernel-proxy.md) | `qiling/os/posix/kernel_proxy/`, `TODO.md` | Opt-in forwarding of chosen syscalls to a real Linux kernel via a helper process | work on the hybrid kernel roadmap, the IPC protocol, proxy fds, or `forward_syscall`. Partners: os-posix, os-base |
| [os-windows.md](ARCHITECTURE/os-windows.md) | `qiling/os/windows/`, `qiling/os/uefi/`, `qiling/os/dos/` | Win32/NT API emulation and kernel objects, UEFI services/protocols, DOS interrupts | add a Win32 API or UEFI protocol, change handles/registry/fibers/threads, touch DOS interrupts. Partners: loader, os-base, arch |
| [os-baremetal.md](ARCHITECTURE/os-baremetal.md) | `qiling/os/mcu/`, `qiling/os/blob/`, `qiling/extensions/multitask.py` | MCU and raw-blob run loops, cooperative multitasking over Unicorn | change stepping/fast mode, interrupt delivery timing, blob execution. Partners: hw, arch, loader |
| [hw.md](ARCHITECTURE/hw.md) | `qiling/hw/`, `qiling/extensions/mcu/` | MMIO peripherals, hardware manager, chip `env` maps | add a peripheral or chip, change MMIO routing or peripheral hooks. Partners: os-baremetal, loader, os-base |
| [debugger.md](ARCHITECTURE/debugger.md) | `qiling/debugger/` | GDB remote-serial server and Qdb (stepping, branch prediction, record/replay) | change RSP handling, target XML, Qdb commands or per-arch support. Partners: core, arch |
| [extensions.md](ARCHITECTURE/extensions.md) | `qiling/extensions/` (except `multitask.py`, `mcu/`) | AFL fuzzing, coverage/trace writers, heap sanitizer, r2/IDA integration, pipes, reports, SDK stub generator | add a coverage/trace format, fuzzing harness support, sanitizer, or analysis integration. Partners: core, os-base, cli |
| [cli.md](ARCHITECTURE/cli.md) | `qltool`, `qiling/cli.py`, `qltui.py` | `qltool` subcommands/flags and the TUI; packaging smoke test | add or change a CLI flag, TUI prompt, or console-script behavior. Partners: core, debugger, extensions |
