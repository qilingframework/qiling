---
eatmycode_version: "1.1.0"
---

# Debugger — GDB server and Qdb

## Goal

Let users debug emulated targets: a GDB remote-serial-protocol server so
any GDB/IDA/lldb front end can attach cross-architecture, and Qdb, a
built-in interactive debugger with stepping, branch prediction, and
record/replay reverse debugging. Owns both front ends and their per-arch
tables; it must not own register or memory semantics. No roadmap
milestone applies; maturity-based status.

## Status

`done` — Qdb covered by `tests/test_qdb.py` (observed: `Ran 6 tests … OK`,
including RISC-V 32/64); the GDB server by `tests/test_debugger.py`
(observed: `Ran 7 tests … OK`, ~71 s, drives scripted clients on port 9999).

## Code Structure

| File | Role |
| ---- | ---- |
| `qiling/debugger/debugger.py` | Base `QlDebugger` |
| `qiling/debugger/gdb/gdb.py` | `QlGdb`: RSP packet handlers (`handle_c/g/G/m/M/q/v/s/X/Z/z`), `GdbSerialConn` socket transport |
| `qiling/debugger/gdb/utils.py` | `QlGdbUtils`: breakpoint table and the per-instruction `dbg_hook` servicing breakpoints, stepping, and async interrupts |
| `qiling/debugger/gdb/xmlregs.py`, `gdb/xml/<arch>/` | `QlGdbFeatures`: target-description XML per arch (a8086, x86, x8664, arm, arm64, cortex_m, mips, ppc, riscv, riscv64) |
| `qiling/debugger/qdb/qdb.py` | `QlQdb(Cmd, QlDebugger)`: command loop (`do_run/step_in/step_over/continue/backward/breakpoint/…`) |
| `qiling/debugger/qdb/arch/` | Per-arch register naming/aliases (arm, cortex-m, intel, mips, riscv) |
| `qiling/debugger/qdb/branch_predictor/` | Predicts branch targets for step/next per arch |
| `qiling/debugger/qdb/render/` | Register/stack/disasm context rendering per arch |
| `qiling/debugger/qdb/utils.py`, `helper.py`, `context.py`, `misc.py`, `const.py` | Factories (`setup_branch_predictor`, `setup_context_render`), `SnapshotManager` for rr, expression helper |

## Language and Conventions

Python; root rules apply. Local patterns:

- GDB packet handlers are closures named `handle_<letter>` inside
  `QlGdb.run` (`qiling/debugger/gdb/gdb.py:248-762`) returning a reply
  string; stop replies use `SIGTRAP` (`:49`) for breakpoints and steps and
  `SIGINT` for async interrupts (`:262-265`).
- Qdb commands are `do_<name>` methods on `QlQdb`
  (`qiling/debugger/qdb/qdb.py:204-691`).
- Per-arch Qdb support is three parallel class families selected by
  `QL_ARCH` maps in `qiling/debugger/qdb/utils.py:109-146`; RISC-V was
  added following that pattern (`qiling/debugger/qdb/arch/arch_riscv.py:11`,
  `branch_predictor_riscv.py`, `render_riscv.py`).
- `qiling/debugger/qdb/branch_predictor/__init__.py:13-17` contains
  tab-indented lines; do not add more.

## Design and Invariants

- **Activation**: `ql.debugger = True | "gdb" | "gdb:HOST:PORT" | "qdb" |
  "qdb:rr" | "qdb:<script>"` (`qiling/core.py:437`); `select_debugger`
  parses the string (`qiling/utils.py:332-373`); the instance is created in
  `Qiling.run` before `os.run()` and `run()`s afterwards
  (`qiling/core.py:577-592`).
- **GDB server** hooks the entry point to pause the guest, then serves
  packets over `GdbSerialConn`; `QlGdbUtils.dbg_hook` runs on every
  instruction (`hook_code`) to service software breakpoints, single-step,
  and a throttled poll for a client `\x03` interrupt
  (`qiling/debugger/gdb/utils.py:57-88`, `INTR_POLL_INTERVAL`).
- **Target description**: `QlGdbFeatures` loads `gdb/xml/<arch>/target.xml`
  with includes and derives the register map served for `qXfer:features`
  (`qiling/debugger/gdb/xmlregs.py:56-137`, `qiling/debugger/gdb/gdb.py:488`).
- **Qdb** installs a breakpoint hook and drives `ql.emu_start` per
  step; branch predictors compute the next pc for `step_over`; `rr` mode
  snapshots full state per step in `SnapshotManager`
  (`qiling/debugger/qdb/utils.py:260`) for `do_backward`.
- **State access** goes through `ql.arch.regs`, `ql.mem`, and
  `hook_address`; the one concrete-type import is `QlProcFS`, used to
  serve `/proc/self/maps` to the client (`qiling/debugger/gdb/gdb.py:38`,
  `:616`).
- Exit reporting: when pc reaches the exit point the server replies
  `W<exit_code>` (`qiling/debugger/gdb/gdb.py:266-269`, `:716-718`);
  bare-metal targets have no
  exit code (issue #1276 comment).

## Key Types and Entry Points

- `qiling/debugger/debugger.py:13` - `QlDebugger` - base; `run()` (`:17`).
- `qiling/debugger/gdb/gdb.py:84` - `QlGdb(QlDebugger)` - `__init__(ql, ip,
  port)` (`:88`), `run()` (`:139`) serves the session.
- `qiling/debugger/gdb/gdb.py:820` - `GdbSerialConn` - transport;
  `poll_interrupt()` (`:859`) wired into `QlGdbUtils.check_interrupt`
  (`:145`).
- `qiling/debugger/gdb/utils.py:16` - `QlGdbUtils` - `dbg_hook` (`:57`),
  `bp_insert/bp_remove` (`:90`/`:105`), `resume_emu` (`:120`).
- `qiling/debugger/gdb/xmlregs.py:56` - `QlGdbFeatures(archtype, ostype)`.
- `qiling/debugger/qdb/qdb.py:59` - `QlQdb(Cmd, QlDebugger)` -
  `__init__(ql, init_hook, rr, script)` (`:64`), `run_qdb_script` (`:87`),
  `run` (`:197`).
- `qiling/debugger/qdb/utils.py:109` / `:128` - `setup_branch_predictor` /
  `setup_context_render` - per-arch selection.
- `qiling/cli.py:227-229` - `--gdb`, `--qdb`, `--rr` flags ([cli.md](cli.md)).

## Interactions

- Instantiated by [core.md](core.md) at `Qiling.run` time, not
  construction.
- Reads/writes state through [arch.md](arch.md) registers and
  [os-base.md](os-base.md) memory; breakpoints use `hook_address`.
- GDB XML register files must match the arch register tables
  ([arch.md](arch.md)); adding an arch means adding `gdb/xml/<arch>/` and
  the three Qdb families.
- The IDA plugin in [extensions.md](extensions.md) is an alternative front
  end over the same public API.

## How to Test

```sh
cd tests && python3 test_qdb.py   # pass = "Ran 6 tests … OK", exit 0
```

- GDB server: `cd tests && python3 test_debugger.py` — pass =
  `Ran 7 tests … OK`; spawns `QlGdb` on `127.0.0.1:9999` and drives
  `SimpleGdbClient`/`ReadingGdbClient` (`tests/test_debugger.py:18`, `:47`).
- Qdb scripts live in `tests/qdb_scripts/*.qdb` (`arm`, `arm_static`,
  `mips32el`, `riscv32`, `riscv64`, `x86`).

## Review and Refactor Guide

- **New RSP packet**: add a `handle_<letter>` closure in `QlGdb.run` and a
  scripted exchange in `tests/test_debugger.py`.
- **Register changes** require updating `gdb/xml/<arch>/*.xml` and the
  Qdb `arch_<name>.py` alias table together.
- **Stop-reply semantics** (`SIGTRAP`/`SIGINT`/`W`) are a client-visible
  contract; changing them needs a test in `tests/test_debugger.py`.
- **Do not** reach into Unicorn directly; use `ql.arch.regs`/`ql.mem` so
  hooks and thumb handling stay consistent.
- Improvement candidate (proposal): fix the a8086 register naming in stop
  replies (FIXME at `qiling/debugger/gdb/gdb.py:242`). Success check: a
  DOS target attach case in `tests/test_debugger.py`.

## Open Gaps / Roadmap

- Qdb has no PowerPC support (`qiling/debugger/qdb/arch/`); GDB XML covers
  all ten arches.
- Record/replay stores full state per step; memory-heavy on long runs.
- `TODO.md:628-636` lists bare `except:` blocks in `qiling/debugger/qdb/qdb.py`.
