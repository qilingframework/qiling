---
eatmycode_version: "1.1.0"
---

# Extensions — optional tooling on top of the core

## Goal

House everything that builds on the public `Qiling` API without being
required by it: AFL fuzzing, code-coverage and execution-trace writers,
disassembly tracing, a heap sanitizer, radare2 and IDA Pro integration,
fake stdio pipes, JSON run reports, and the Windows SDK stub generator.
Two files under this package are owned elsewhere: `multitask.py`
([os-baremetal.md](os-baremetal.md)) and `mcu/` ([hw.md](hw.md)). The
kernel proxy is not here; see [kernel-proxy.md](kernel-proxy.md). No
roadmap milestone applies; maturity-based status.

## Status

`done` — the history coverage tracker is tested in CI (observed:
`Ran 4 tests … OK`); pipes are exercised by many suites; AFL and r2 need
optional extras (`fuzz`, `RE`) and are untested here; the IDA plugin needs
IDA Pro and is untested in CI.

## Code Structure

| File | Role |
| ---- | ---- |
| `qiling/extensions/afl/afl.py`, `qlfuzzer.py` | `ql_afl_fuzz` / `ql_afl_fuzz_custom` (unicornafl bridge) and the `QlFuzzer` harness base |
| `qiling/extensions/coverage/utils.py`, `formats/` | `collect_coverage` context manager; `CoverageFactory` over `QlBaseCoverage` subclasses (`drcov`, `drcov_exact`, `ezcov`, `history`) |
| `qiling/extensions/tracing/utils.py`, `formats/` | `collect_trace`; Tenet-style trace writers (`tenet`, `registers`) |
| `qiling/extensions/trace.py` | Disassembly tracing: full trace or ring-buffer history |
| `qiling/extensions/sanitizers/heap.py` | `QlSanitizedMemoryHeap`: canary-based heap sanitizer (UAF/OOB) |
| `qiling/extensions/r2/r2.py` | `R2(ql)`: r2libr-backed sections/symbols/functions/xrefs of the loaded target |
| `qiling/extensions/idaplugin/qilingida.py` | IDA Pro plugin driving Qiling from IDA (`PLUGIN_ENTRY`) |
| `qiling/extensions/pipe.py` | `SimpleInStream`/`SimpleOutStream`/`NullOutStream`/`InteractiveInStream` fake stdio |
| `qiling/extensions/report/report.py` | `generate_report(ql)`: JSON summary of a run |
| `qiling/extensions/winsdkapi.py` | CLI generator emitting `@winsdkapi` stubs from Windows SDK JSON |

## Language and Conventions

Python; root rules apply. Coverage and trace writers register by
subclassing a base with a `FORMAT_NAME` class attribute
(`qiling/extensions/coverage/formats/base.py:16-23`,
`qiling/extensions/coverage/formats/drcov.py:29-38`) and are discovered by
`get_all_subclasses` (`qiling/extensions/coverage/utils.py:34`). Optional
dependencies are imported lazily inside the modules that need them
(`qiling/extensions/afl/afl.py`, `qiling/extensions/r2/r2.py`) so the core never
requires `unicornafl` or `r2libr`. The IDA plugin is a single 2.3k-line
file with IDA-specific conventions; treat it as its own style domain.

## Design and Invariants

- Everything here consumes only public APIs of [core.md](core.md) (hooks,
  `mem`, `arch.regs`, `save/restore`) and [os-base.md](os-base.md) (heap,
  stdio, `set_syscall`/`set_api`). Nothing in `qiling/os`, `qiling/loader`,
  or `qiling/arch` may import from here except the documented cases:
  `qiling/cli.py:22-23` for coverage/report, `qiling/arch/utils.py:94`
  lazy r2, and the multitask/mcu owners noted above.
- `collect_coverage` activates hooks on enter and dumps on exit even on
  exceptions (`qiling/extensions/coverage/utils.py:48-63`); `qltool
  --coverage-format` lists `factory.formats` (`qiling/cli.py:240`).
- The heap sanitizer replaces `ql.os.heap` with a compatible object that
  surrounds chunks with canaries and detects double-free/UAF; it hooks
  memory access to report faults (`qiling/extensions/sanitizers/heap.py:29`).
- `pipe.py` streams implement the `ql_file` surface expected by the fd
  table so they can be assigned to `ql.os.stdin/stdout/stderr`.
- AFL: `ql_afl_fuzz` wraps `unicornafl.uc_afl_fuzz` with input placement,
  crash validation, and exit points; `QlFuzzer` builds a harness with
  `stage_call_site`/`feed_input` (`qiling/extensions/afl/qlfuzzer.py:75`, `:86`).

## Key Types and Entry Points

- `qiling/extensions/afl/afl.py:21` / `:87` - `ql_afl_fuzz` /
  `ql_afl_fuzz_custom`; `qiling/extensions/afl/qlfuzzer.py:14` - `QlFuzzer(ABC)`.
- `qiling/extensions/coverage/utils.py:48` - `collect_coverage(ql, name,
  coverage_file)`; `:32` - `CoverageFactory`.
- `qiling/extensions/tracing/utils.py:31` - `collect_trace(ql, name, trace_file)`.
- `qiling/extensions/trace.py:145` / `:180` - `enable_full_trace` /
  `enable_history_trace`.
- `qiling/extensions/sanitizers/heap.py:16` - `QlSanitizedMemoryHeap(ql,
  heap, fault_rate, canary_byte)`.
- `qiling/extensions/r2/r2.py:135` - `R2(ql)`.
- `qiling/extensions/pipe.py:62` / `:69` - `SimpleInStream` / `SimpleOutStream`;
  `:98` - `InteractiveInStream`.
- `qiling/extensions/report/report.py:56` - `generate_report(ql, pretty_print)`.
- `qiling/extensions/coverage/formats/history.py:13` - `History` - tested
  tracker (`tests/test_history.py`).

## Interactions

- [cli.md](cli.md) wires `--coverage-file/--coverage-format` and `--json`
  (`qiling/cli.py:306-320`).
- The heap sanitizer wraps `QlMemoryHeap` ([os-base.md](os-base.md));
  demo `examples/uefi_sanitized_heap.py` with [os-windows.md](os-windows.md)
  UEFI, proven by `tests/test_uefi.py:24`.
- Fuzzing harnesses in `examples/fuzzing/{linux_x8664,qnx_arm,stm32f429,
  tenda_ac15,dlink_dir815,rt_n12_b1}` pair AFL with `pipe.py` and
  `set_syscall` ([os-posix.md](os-posix.md)) or MCU mode
  ([os-baremetal.md](os-baremetal.md)).
- `pipe.py` is used by `tests/test_pe.py`, `test_windows_stdio.py`,
  `test_riscv.py`, `test_windows_cpp_x86.py`, and `test_kernel_proxy.py`.
- The IDA plugin offers a front end comparable to [debugger.md](debugger.md).

## How to Test

```sh
cd tests && python3 test_history.py   # pass = "Ran 4 tests … OK", exit 0
```

- Coverage output end-to-end: `tests/test_qltool.py::test_qltool_coverage`
  (drcov) and `::test_qltool_json` (report).
- r2 (needs `pip install qiling[RE]`): `cd tests && python3 test_r2.py`
  (skips without `r2libr`, `tests/test_r2.py:20`).
- AFL (needs `pip install qiling[fuzz]` and AFL++): run a harness from
  `examples/fuzzing/linux_x8664/` (`fuzz.sh`); not automated.

## Review and Refactor Guide

- **New coverage/trace format**: subclass the base with a unique
  `FORMAT_NAME`; no registry edit needed.
- **New extension**: keep imports to public `Qiling` API; put optional
  third-party dependencies behind a Poetry extra (root Dependencies
  deviation) and import them lazily.
- **Do not** import extensions from `qiling/os`, `qiling/loader`, or
  `qiling/arch`; move shared code into the owning core module instead.
- Improvement candidate (proposal): unify `trace.py` and `tracing/` behind
  one factory. Success check: `qltool` exposes trace formats like coverage
  formats and `tests/test_history.py` stays green.

## Open Gaps / Roadmap

- `afl/` and `r2/` depend on optional extras not installed by default;
  the IDA plugin cannot be CI-tested.
- Two overlapping trace mechanisms exist (`trace.py` and `tracing/`).
- `tests/test_perf.py` and `tests/view_perf_results.py` are ad-hoc
  performance tools without assertions.
