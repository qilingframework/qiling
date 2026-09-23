---
eatmycode_version: "2.1.0"
---

# Instrumentation and Integrations

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: changing qiling/extensions/ except mcu/ and multitask.py, fuzzing harnesses, coverage/trace formats, sanitizers or analysis adapters.

## Responsibility and Status

Owns coverage/history, trace output, AFL integration, heap sanitizer,
reports, pipes, r2/IDA adapters and Windows SDK stub tooling.
**In progress:** history and UEFI sanitizer tests pass; optional fuzz/RE/IDA
integrations and all output formats remain unverified. Firmware extension
paths are explicitly owned by hardware/bare-metal modules.

## Code Map

| Path / symbol | Role |
| --- | --- |
| [coverage/utils.py](../../qiling/extensions/coverage/utils.py): `CoverageFactory`, `collect_coverage`; [coverage/formats/](../../qiling/extensions/coverage/formats/) | Format discovery, hook lifecycle, history and output |
| [tracing/utils.py](../../qiling/extensions/tracing/utils.py), [tracing/formats/](../../qiling/extensions/tracing/formats/), [trace.py](../../qiling/extensions/trace.py) | Trace collectors and log/history tracing |
| [afl/afl.py](../../qiling/extensions/afl/afl.py): `ql_afl_fuzz`, `ql_afl_fuzz_custom`; [afl/](../../qiling/extensions/afl/) | Input/crash callback bridge and engine integrations |
| [sanitizers/heap.py](../../qiling/extensions/sanitizers/heap.py): `QlSanitizedMemoryHeap` | Allocation wrapping and memory-error hooks |
| [report/](../../qiling/extensions/report/), [pipe.py](../../qiling/extensions/pipe.py), [r2/](../../qiling/extensions/r2/), [idaplugin/](../../qiling/extensions/idaplugin/), [winsdkapi.py](../../qiling/extensions/winsdkapi.py) | Reporting, I/O adapters, optional analysis and stub generation |
| [test_history.py](../../tests/test_history.py), [test_uefi.py](../../tests/test_uefi.py), [test_r2.py](../../tests/test_r2.py), [examples/fuzzing/](../../examples/fuzzing/) | History/sanitizer/integration evidence and harness sources |

## Local Conventions

Use [root conventions](../../ARCHITECTURE.md#code-conventions); optional
packages use manifest extras `fuzz` and `RE`. Format classes expose
`FORMAT_NAME` and activate/deactivate/dump methods; imports register subclasses
with factories. No common C standard is declared for fuzz harnesses; inspect
the local `fuzz.c`/build instructions. Generated SDK stubs require review;
they are not automatically complete Windows API behavior.

## Contracts and Invariants

- Coverage context manager always deactivates hooks and dumps output in
  `finally`. Tracing likewise deactivates and writes when an output path is
  supplied. New formats must register before the factory is constructed.
- History derives executable-image ranges from memory metadata; labels and
  image identities matter to filtering (`coverage/formats/history.py`).
- AFL delegates input placement and crash validation to user callbacks,
  configures engine exit addresses and supports persistent iterations.
  The harness owns resetting all state/input that survives an iteration;
  callbacks must not confuse guest addresses with host buffers (`afl.py`).
- Sanitized heap wraps allocations with memory hooks/canaries. Caller
  failure callbacks determine response; inspect actual hook coverage before
  claiming detection of every memory error.
- Reports and traces serialize observed emulator state; they are not full
  snapshots. r2/IDA depend on separately available runtimes and may use
  concrete emulator types. Host file output and native integrations retain
  their own resource lifetimes.

## Dependencies and Boundaries

Read [core](core.md) for hooks/lifecycle, [OS base](os-base.md) for heap and
mapping state, [arch](arch.md) for register/decoder output, and
[CLI/build](cli-build.md) when flags or output choices change. Read
[Windows](windows.md) when modifying SDK-generated hook contracts.
Firmware-only exceptions use the root firmware branch, not this owner.

## Change Guide

| Change trigger | Inspect / extend | Required docs / checks |
| --- | --- | --- |
| Coverage/trace format | Base class, exports/factory, cleanup/output | History/CLI output regression; root CLI owner for flags |
| Fuzzing lifecycle | Input/crash callbacks, exits, persistent state | Harness-specific run with correct extra/runtime; core/arch as affected |
| Sanitizer/report/adapter | Hook lifetime, serialized fields, external API | Direct UEFI/history or adapter test; consumer owner |

## Verification

From `tests/`: `python -m unittest test_history` passed 4 tests;
`python test_uefi.py` passed 2 direct integration tests including sanitizer
behavior. For coverage output run
`python -m unittest test_qltool.Qltool_Test.test_qltool_coverage` with UEFI
fixtures; that coverage case also passed during the latest refresh. For r2 changes use `python test_r2.py` after root setup with `RE`;
this optional check was not run. AFL/IDA require their external runtimes and
matching harnesses; a base-package import does not validate them.

## Known Gaps

No complete fuzz/IDA/trace/report regression suite is configured. Existing
coverage/tracing factory similarity is observed, not a mandate to refactor
unrelated formats. Native optional integration compatibility and all
persistent-state reset contracts remain unverified.
