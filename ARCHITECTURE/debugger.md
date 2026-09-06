# Debugger — GDB server and Qdb

## Goal

Let users debug emulated targets: a GDB remote-serial-protocol server so any
GDB/IDA/lldb front end can attach cross-architecture, and Qdb — a built-in
interactive CLI debugger with stepping, branch prediction, and record/replay
reverse debugging. Mature released infrastructure; maturity-based status.

## Status

`done` — Qdb covered by `tests/test_qdb.py`; the GDB server by
`tests/test_debugger.py` (spawns a real client session).

## Code Structure

| File | Role |
| ---- | ---- |
| `qiling/debugger/debugger.py` | Base `QlDebugger` |
| `qiling/debugger/gdb/gdb.py` | `QlGdb`: GDB remote-serial-protocol server, plus the `GdbSerialConn` transport |
| `qiling/debugger/gdb/utils.py` | `QlGdbUtils`: breakpoint table and the per-instruction `dbg_hook` that services breakpoints, stepping, and async interrupts |
| `qiling/debugger/gdb/xmlregs.py`, `gdb/xml/` | Target-description XML per arch for modern GDB clients |
| `qiling/debugger/qdb/qdb.py` | `QlQdb`: interactive Cmd-based debugger |
| `qiling/debugger/qdb/arch/` | Per-arch Qdb support (arm, intel, mips) |
| `qiling/debugger/qdb/branch_predictor/` | Predicts branch targets for step/next |
| `qiling/debugger/qdb/render/` | Register/stack/disasm view rendering |

## Key Types and Entry Points

- `qiling/debugger/debugger.py:13` - `QlDebugger` - base; `run()` starts the session.
- `qiling/debugger/gdb/gdb.py:84` - `QlGdb(QlDebugger)` - listens on ip:port, translates RSP packets to Qiling hook/mem/reg operations; `run()` (`:139`) serves the session.
- `qiling/debugger/gdb/gdb.py:817` - `GdbSerialConn` - the socket transport; `poll_interrupt()` (`:856`) is a non-blocking check for a client `\x03`, wired into `QlGdbUtils.check_interrupt` (`qiling/debugger/gdb/gdb.py:145`) so a running guest can be broken into asynchronously.
- `qiling/debugger/gdb/utils.py:16` - `QlGdbUtils` - `dbg_hook` (`:48`) runs per instruction to service breakpoints, single-step, and interrupts; `bp_insert`/`bp_remove` (`:81`/`:94`); `resume_emu` (`:107`).
- Stop replies report `SIGTRAP` (`qiling/debugger/gdb/gdb.py:49`) for both single-step (`:243`) and async-interrupt stops (`:262`).
- `qiling/debugger/qdb/qdb.py:59` - `QlQdb(Cmd, QlDebugger)` - CLI loop; `rr` mode enables record/replay reverse debugging.
- Activation: set `ql.debugger = True | "gdb" | "gdb:0.0.0.0:9999" | "qdb" | "qdb:rr"` (`qiling/core.py:437`); instantiated lazily in `Qiling.run` via `select_debugger` (`qiling/utils.py:332`).
- `qltool` flags: `--gdb` and `--qdb` (see [cli.md](cli.md)).

## Interactions

- Instantiated by [core.md](core.md) at `Qiling.run` time, not construction.
- Reads/writes state exclusively through public APIs: registers via [arch.md](arch.md), memory via [os-base.md](os-base.md), breakpoints via `hook_address` ([core.md](core.md)).
- The IDA plugin in [extensions.md](extensions.md) offers an alternative front end over the same public API.

## How to Test

```sh
cd tests && python3 test_qdb.py   # pass = unittest "OK", exit 0
```

- GDB server: `cd tests && python3 test_debugger.py` — starts `QlGdb` and drives a scripted client.

## Open Gaps / Roadmap

- Qdb per-arch support covers arm/cortex-m/mips/intel; RISC-V and PPC lack Qdb arch modules (`qiling/debugger/qdb/arch/`).
- Record/replay (`qdb:rr`) stores full state per step — memory-heavy on long runs.
