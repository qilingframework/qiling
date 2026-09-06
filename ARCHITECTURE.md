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
- **Python**: 3.10+ (`pyproject.toml:37`). Packaging via Poetry; version
  1.4.11.dev0 (`pyproject.toml:4`), status Beta, license GPL-2.0-or-later.
- **Core dependencies**: `unicorn ==2.1.3` (hard-pinned CPU emulator,
  `pyproject.toml:39`), `capstone` (disassembly), `keystone-engine`
  (assembly), `pefile`, `pyelftools`, `python-registry`, `gevent`
  (multithread emulation), `pyyaml` (MCU profiles). Extras: `fuzz` →
  unicornafl/fuzzercorn, `RE` → r2libr.
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
| `qltool` / `qiling/cli.py` | Checkout launcher / installed CLI implementation (see [cli.md](ARCHITECTURE/cli.md)) |
| `qltui.py` | Terminal UI invoked via `qltool qltui` |
| `Dockerfile` | Multi-stage Poetry wheel build on `python:3-slim` |
| `pyproject.toml` / `poetry.lock` | Packaging and dependency pins |
| `.github/workflows/` | CI (`build-ci.yml`: Windows + Ubuntu × Python 3.11/3.13, plus a Docker container job), Docker publish, PyPI publish, Gitee mirror sync |

## Boot / Entry Flow

From CLI to emulated instructions (details live in the module docs):

1. `qltool` calls `qiling.cli.run`, which parses args and builds kwargs;
   `run` and `code` subcommands end in `Qiling(**ql_args)`
   (`qiling/cli.py:276`) — see [cli.md](ARCHITECTURE/cli.md).
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

Maturity-based — Qiling is a released project in maintenance/beta
(v1.4.11.dev0). There are no in-repo milestones; module Status is `done` when
its test suite proves it. Feature requests and the forward-looking wishlist are tracked in
GitHub issue [#333](https://github.com/qilingframework/qiling/issues/333)
(the `TODO` file is a pointer to it). Known cross-cutting gaps:

- `ChangeLog` stops at 1.4.6 (`ChangeLog:4`) while `pyproject.toml:4` says
  1.4.11.dev0.
- macOS is dropped from the CI matrix and the macOS/kext job is commented out
  (`.github/workflows/build-ci.yml:12`, `:84`).
- `jexamples/` is legacy and unexercised by CI.

## Packaging and Releases

`.github/workflows/pythonpublish.yml` validates metadata and the lock file,
builds a source distribution and a wheel from it, checks both with Twine,
and runs `InstalledQltool_Test` against the installed wheel outside the
checkout. Builds run on pushes and pull requests; publishing runs on tags.

Before tagging a release, set its version with `poetry version <version>`
and commit the change. The tag must match the package version under PEP 440
normalization, with an optional `v` prefix. Development versions remain
prereleases; a stable release requires a stable version in `pyproject.toml`.
Publishing uploads to TestPyPI, then PyPI, using the existing
`testpypi_pass` and `pypi_pass` API-token secrets. TestPyPI skips existing
files so a production upload can be retried after TestPyPI succeeds.

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
narrowest supported assumptions. Ask one focused question only when a
required decision cannot be discovered or safely inferred and guessing
would materially change the result. Once framed, continue without an
approval pause.

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

- A new maintainer can build, test, run, and understand public behavior
  from the docs.
- Every changed line serves the goal; no drive-by formatting, debugging
  remnants, commented-out code, secrets, tokens, or local paths remain.
- Public names, signatures, errors, and recovery are intelligible.
- Architecture docs and `file:line` references are current.
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
- Never widen scope to satisfy a finding. Record out-of-scope work under
  **Open Gaps / Roadmap**.

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
scope, layering, ownership, public-API growth, and performance claims. A
layering violation or unjustified public API is `major`. Architectural or
public-behavior changes must update the relevant docs in the same change.

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

### Project-Specific Deviations

- **Security, scope.** Qiling *emulates* untrusted binaries; guest code
  doing something hostile inside the sandbox is the product working, not
  a finding. Findings target the host boundary: rootfs escape via path
  handling (`qiling/os/path.py`), unchecked guest-controlled sizes or
  offsets reaching host allocations or `struct` unpacking, and parser
  input in `qiling/loader/` reachable from an untrusted image.
- **Dependencies.** `pyproject.toml` is the only manifest. A new
  top-level runtime dependency is `blocker` absent an explicit request;
  optional integrations belong in an extra (`fuzz`, `RE`).

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
