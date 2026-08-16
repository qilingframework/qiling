# Qiling Framework — Architecture

This is the control center for agent-readable architecture docs. Cross-cutting
facts live here; each subsystem is documented once in `ARCHITECTURE/<module>.md`
(see the [Index](#index)).

## Mission

Qiling is an advanced binary emulation framework: it emulates and sandboxes
code in an isolated environment across multiple platforms and architectures.
Built on top of Unicorn Engine, it adds what raw CPU emulation lacks —
operating-system context (syscalls, APIs, filesystems, registries), executable
format loading, and dynamic linking (`README.md:13`).

Supported combinations are defined authoritatively in code:

- Architectures — `QL_ARCH` (`qiling/const.py:15`): 8086, x86, x86-64, ARM,
  ARM64, Cortex-M, MIPS, RISC-V 32/64, PowerPC.
- Operating systems — `QL_OS` (`qiling/const.py:28`): Linux, FreeBSD, macOS,
  Windows, UEFI, DOS, QNX, MCU (bare-metal), BLOB.
- Formats: ELF, PE, Mach-O, COM/MBR, Intel HEX / raw firmware. Kernel-module
  emulation for Windows `.sys`, Linux `.ko`, macOS `.kext`.

Headline capabilities: fine-grained instrumentation hooks (instruction, basic
block, memory access, interrupt, syscall/API), VM state save/restore, dynamic
hot patching, cross-architecture debugging (GDB server and the built-in Qdb
with reverse debugging), and fuzzing integration (AFL++/unicornafl).

## Target Environment

- **Shape**: pure-Python library (`from qiling import Qiling`), plus the
  `qltool` CLI and `qltui.py` TUI. Also shipped as a Docker image
  (`Dockerfile`) and PyPI package.
- **Python**: 3.8+ (`pyproject.toml:30`). Packaging via Poetry; version 1.4.8
  (`pyproject.toml:4`), status Beta, license GPLv2.
- **Core dependencies**: `unicorn ==2.1.3` (hard-pinned CPU emulator),
  `capstone` (disassembly), `keystone-engine` (assembly), `pefile`,
  `pyelftools`, `python-registry`, `gevent` (multithread emulation),
  `pyyaml` (MCU profiles). Extras: `fuzz` → unicornafl/fuzzercorn,
  `RE` → r2libr.
- **Hosts**: Linux, Windows, macOS. Some test suites are host-gated (Windows
  PE tests need real system DLLs collected on Windows; see
  [os-windows.md](ARCHITECTURE/os-windows.md)).
- **Fixtures**: `examples/rootfs/` is a git submodule
  (https://github.com/qilingframework/rootfs.git) holding target binaries for
  tests and examples.

## Workspace Layout

| Path | Holds |
| ---- | ----- |
| `qiling/` | The framework package (see Index for per-subsystem docs) |
| `qiling/profiles/` | Default per-OS config profiles (`linux.ql`, `windows.ql`, …) |
| `examples/` | Curated demo scripts, `fuzzing/`, `mcu/`, `shellcodes/`, `extensions/`, `scripts/` (DLL collectors), and the `rootfs/` submodule |
| `jexamples/` | Legacy example set (not covered by CI) |
| `tests/` | CI test suite — standalone `unittest` files run from `tests/` (`tests/test_onlinux.sh`, `tests/test_pe.bat`, `tests/test_macho.sh`) |
| `docs/` | Stubs and assets; real documentation lives at https://docs.qiling.io |
| `qltool` | CLI entry point (see [cli.md](ARCHITECTURE/cli.md)) |
| `qltui.py` | Terminal UI invoked via `qltool qltui` |
| `Dockerfile` | Multi-stage Poetry wheel build on `python:3-slim` |
| `pyproject.toml` / `poetry.lock` | Packaging and dependency pins |
| `.github/workflows/` | CI (`build-ci.yml`: Windows + Ubuntu × Python 3.9/3.11), Docker publish, PyPI publish, Gitee mirror sync |

## Boot / Entry Flow

From CLI to emulated instructions (details live in the module docs):

1. `qltool` parses args and builds kwargs; `run` and `code` subcommands end in
   `Qiling(**ql_args)` (`qltool:276`) — see [cli.md](ARCHITECTURE/cli.md).
2. `Qiling.__init__` (`qiling/core.py:35`) is the composition root. Order:
   guess arch/OS from the binary if not given → instantiate arch → init
   struct/hook mixins → logger → profile → loader → memory manager → OS layer
   → hardware manager (bare-metal only) → `loader.run()` maps the target into
   emulated memory (`qiling/core.py:154-195`). All name→class resolution is in
   `qiling/utils.py` — see [core.md](ARCHITECTURE/core.md).
3. `Qiling.run()` (`qiling/core.py:561`) attaches the debugger if configured,
   applies queued patches, writes the exit trap, then delegates to
   `os.run()` — see [debugger.md](ARCHITECTURE/debugger.md) and the OS docs.
4. The OS layer drives `Qiling.emu_start` (`qiling/core.py:743`), the thin
   wrapper over Unicorn's `uc.emu_start`. Syscalls/APIs raised by the emulated
   code are dispatched back into the OS layer
   ([os-posix.md](ARCHITECTURE/os-posix.md),
   [os-windows.md](ARCHITECTURE/os-windows.md),
   [os-baremetal.md](ARCHITECTURE/os-baremetal.md)).

## Roadmap

Maturity-based — Qiling is a released project in maintenance/beta (v1.4.8).
There are no in-repo milestones; module Status is `done` when its test suite
proves it. Feature requests and the forward-looking wishlist are tracked in
GitHub issue [#333](https://github.com/qilingframework/qiling/issues/333)
(the `TODO` file is a pointer to it). Known cross-cutting gaps:

- `ChangeLog` stops at 1.4.6 while `pyproject.toml` says 1.4.8.
- macOS CI job is commented out in `.github/workflows/build-ci.yml`.
- `jexamples/` is legacy and unexercised by CI.

## Coding Discipline

Behavioral guidelines to reduce common LLM coding mistakes. Merge with
project-specific instructions as needed.

**Tradeoff:** These guidelines bias toward caution over speed. For
trivial tasks, use judgment.

### 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

### 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If
yes, simplify.

### 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

### 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:

```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make
it work") require constant clarification.

---

**These guidelines are working if:** fewer unnecessary changes in diffs,
fewer rewrites due to overcomplication, and clarifying questions come
before implementation rather than after mistakes.

## Index

- [core.md](ARCHITECTURE/core.md) — the `Qiling` facade, hook engine, component selection, profiles, logging, exceptions
- [arch.md](ARCHITECTURE/arch.md) — CPU layer: registers, Unicorn instance, disassembler, calling conventions
- [loader.md](ARCHITECTURE/loader.md) — binary format loaders: ELF, PE, PE/UEFI, Mach-O, DOS, MCU firmware, raw blobs
- [os-base.md](ARCHITECTURE/os-base.md) — shared OS layer: `QlOs`, memory manager/heap, fcall marshalling, fs mapper, path virtualization
- [os-posix.md](ARCHITECTURE/os-posix.md) — POSIX syscall emulation: Linux, FreeBSD, macOS, QNX
- [os-windows.md](ARCHITECTURE/os-windows.md) — Windows API emulation, UEFI boot/runtime/SMM services, DOS interrupts
- [os-baremetal.md](ARCHITECTURE/os-baremetal.md) — MCU and raw-blob execution modes, cooperative multitasking
- [hw.md](ARCHITECTURE/hw.md) — MMIO peripheral emulation for bare-metal targets, board/chip definitions
- [debugger.md](ARCHITECTURE/debugger.md) — GDB remote-serial server and the built-in Qdb debugger
- [extensions.md](ARCHITECTURE/extensions.md) — AFL fuzzing, coverage/tracing, sanitizers, r2/IDA integration, pipes, reports
- [cli.md](ARCHITECTURE/cli.md) — `qltool` CLI and `qltui.py` TUI
