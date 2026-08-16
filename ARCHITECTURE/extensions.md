# Extensions — optional tooling on top of the core

## Goal

House everything that builds on the public `Qiling` API without being required
by it: fuzzing (AFL), code-coverage and execution-trace writers, a heap
sanitizer, radare2 and IDA Pro integration, fake stdio pipes, and JSON run
reports. Mature released infrastructure; maturity-based status.

## Status

`done` — history/coverage tracker tested in CI; AFL and r2 integrations need
optional extras (`fuzz`, `RE`); the IDA plugin needs IDA Pro (untested in CI).

## Code Structure

| File | Role |
| ---- | ---- |
| `qiling/extensions/afl/` | `ql_afl_fuzz` (unicornafl bridge) + `QlFuzzer` harness base class |
| `qiling/extensions/coverage/` | `collect_coverage` context manager; writers in `formats/` (drcov, drcov_exact, ezcov, history) |
| `qiling/extensions/tracing/` | Tenet-style execution trace writers (`formats/`) |
| `qiling/extensions/trace.py` | Disassembly tracing: full trace or ring-buffer history |
| `qiling/extensions/sanitizers/heap.py` | Canary-based heap sanitizer (UAF/OOB detection) |
| `qiling/extensions/r2/r2.py` | radare2 (r2libr) integration: sections/symbols/functions/xrefs of the loaded target |
| `qiling/extensions/idaplugin/qilingida.py` | IDA Pro plugin driving Qiling emulation from IDA |
| `qiling/extensions/pipe.py` | Fake stdio streams for hijacking emulated I/O (fuzzing staple) |
| `qiling/extensions/report/report.py` | `generate_report(ql)`: JSON summary of a run |
| `qiling/extensions/multitask.py` | Cooperative-multitask Unicorn wrapper (documented in [os-baremetal.md](os-baremetal.md)) |
| `qiling/extensions/mcu/` | Board/chip definitions (documented in [hw.md](hw.md)) |
| `qiling/extensions/winsdkapi.py` | Windows API signature decorator glue |

## Key Types and Entry Points

- `qiling/extensions/afl/afl.py:21` / `:87` - `ql_afl_fuzz` / `ql_afl_fuzz_custom` - hand control to AFL++ via unicornafl; harness base `QlFuzzer` (`qiling/extensions/afl/qlfuzzer.py:14`).
- `qiling/extensions/coverage/utils.py:48` - `collect_coverage(ql, name, file)` - context manager writing e.g. drcov files (used by `qltool --coverage-file`).
- `qiling/extensions/trace.py:145` / `:180` - `enable_full_trace` / `enable_history_trace` - disassembly tracing via `hook_code`.
- `qiling/extensions/sanitizers/heap.py:16` - `QlSanitizedMemoryHeap` - drop-in replacement for `ql.os.heap` with canaries and free-list checks.
- `qiling/extensions/r2/r2.py:135` - `R2(ql)` - rzpipe-backed analysis of the loaded image.
- `qiling/extensions/pipe.py` - `SimpleInStream`/`SimpleOutStream` (`:62`/`:69`) - assigned to `ql.os.stdin`/`stdout`.
- `qiling/extensions/report/report.py:56` - `generate_report(ql)` - JSON report (used by `qltool --json`).

## Interactions

- Everything here consumes only the public API of [core.md](core.md) (hooks, mem, regs) and [os-base.md](os-base.md) (heap, stdio, syscall/API overrides).
- The heap sanitizer wraps `QlMemoryHeap` from [os-base.md](os-base.md) (demo: `examples/uefi_sanitized_heap.py` with [os-windows.md](os-windows.md) UEFI).
- Fuzzing harnesses live in `examples/fuzzing/` and pair AFL with `pipe.py` and `set_syscall` from [os-posix.md](os-posix.md).
- `qltool` wires in coverage and report generation ([cli.md](cli.md)).

## How to Test

```sh
cd tests && python3 test_history.py   # pass = unittest "OK", exit 0
```

- r2 integration (needs `pip install qiling[RE]`): `cd tests && python3 test_r2.py`.
- AFL (needs `pip install qiling[fuzz]` + AFL++): run a harness from `examples/fuzzing/linux_x8664/`.

## Open Gaps / Roadmap

- `afl/` and `r2/` depend on optional extras not installed by default; the IDA plugin cannot be CI-tested (requires an IDA Pro license).
- Two overlapping trace mechanisms exist (`trace.py` and `tracing/`); no unified interface.
