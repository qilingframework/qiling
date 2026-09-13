---
eatmycode_version: "2.0.0"
---

# Debuggers

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: changing qiling/debugger/, GDB packets/register XML, Qdb commands, stepping, breakpoints or replay.

## Responsibility and Status

Owns GDB remote protocol and Qdb's interactive/script debugger, register
rendering, branch prediction and snapshots. **In progress:** selected GDB
signal/interrupt regressions and one Qdb script pass; complete protocol,
architecture and replay coverage is unverified.

## Code Map

| Path / symbol | Role |
| --- | --- |
| [debugger.py](../../qiling/debugger/debugger.py): `QlDebugger` | Shared debugger interface |
| [gdb/gdb.py](../../qiling/debugger/gdb/gdb.py): `QlGdb`; [gdb/utils.py](../../qiling/debugger/gdb/utils.py) | Packet transport, command handling, stop/continue and memory/files |
| [gdb/xmlregs.py](../../qiling/debugger/gdb/xmlregs.py): `QlGdbFeatures`; [gdb/xml/](../../qiling/debugger/gdb/xml/) | Target register descriptions and wire ordering |
| [qdb/qdb.py](../../qiling/debugger/qdb/qdb.py): `QlQdb`; [qdb/utils.py](../../qiling/debugger/qdb/utils.py): `SnapshotManager` | Commands, breakpoints, snapshot/replay and target helpers |
| [qdb/](../../qiling/debugger/qdb/) | Architecture-specific renderers, predictors, disassembly and command helpers |
| [test_debugger.py](../../tests/test_debugger.py), [test_qdb.py](../../tests/test_qdb.py), [qdb_scripts/](../../tests/qdb_scripts/), [test_windows_debugger.py](../../tests/test_windows_debugger.py) | Protocol regression clients and debugger scripts |

## Local Conventions

Use [root conventions](../../ARCHITECTURE.md#code-conventions).
Qdb preserves `cmd.Cmd`'s `do_*` convention and target-specific helpers.
GDB protocol register order/width/encoding comes from target XML, not
Python attribute order. Keep XML licensing/attribution and target meaning;
no repository regeneration pipeline is established for these assets.

## Contracts and Invariants

- Core configures debugger before OS execution. GDB defaults to loopback
  port 9999; attach/detach addresses depend on file versus shellcode/MCU
  paths. Thumb attach addresses are aligned (`QlGdb.__init__`).
- GDB reads/writes emulated registers/memory and exposes supported file
  requests. Preserve packet checksums/framing, target endian/register width
  and stop replies. Unicorn faults map to signals; single-step success
  reports SIGTRAP (`UC_ERROR_SIGMAP`, packet handlers).
- Async Ctrl-C and `vCont` actions must stop/resume the right emulation
  state. Transport handling must not introduce unbounded guest/remote sizes
  reaching host allocation or file access; debugger access is a host boundary.
- Qdb breakpoint handling stops the emulator and flushes translated blocks
  to avoid resuming past a breakpoint. Replay relies on available saved
  state; it cannot promise reversal of host filesystem/socket effects.

## Dependencies and Boundaries

Read [core](core.md) for run/stop/hook lifecycle, [arch](arch.md) for register
and step semantics, [loaders](loaders.md) for image entry/address changes,
[OS base](os-base.md) for memory and [POSIX](posix.md) for GDB procfs/file
behavior. Remote register descriptions are consumed by external clients;
maintain protocol compatibility rather than exposing internal refactors.

## Change Guide

| Change trigger | Inspect / extend | Required docs / checks |
| --- | --- | --- |
| GDB packet/register | Parser, reply encoding, XML maps | Protocol regression; arch owner for layout |
| Step/interrupt/resume | Stop state, fault signals, async input | SIGTRAP/vCont/Ctrl-C cases; core owner |
| Qdb command/replay | Command helper, predictor, snapshots | Matching Qdb script; state owner for replay change |

## Verification

From `tests/`: `python -m unittest test_debugger.DebuggerTest.test_gdbdebug_stepi_reports_sigtrap test_debugger.DebuggerTest.test_gdbdebug_vcont_signal_actions test_debugger.DebuggerTest.test_gdbdebug_async_interrupt`
and `python -m unittest test_qdb.DebuggerTest.test_qdb_arm_hello` passed
3 GDB and 1 Qdb cases. Loopback sockets, free test ports, engine dependencies
and target fixtures are required. For broader changes run
`python test_debugger.py` and `python test_qdb.py`; Windows debugger checks
need Windows fixtures. Follow [shared test-resource rules](cli-build.md#verification)
for port conflicts. Tests use in-process clients, not every external GDB.

## Known Gaps

Full protocol/architecture support and reverse-execution side effects are
unverified. XML declarations do not prove every target is runnable. The
Qdb README and scripts provide command examples, not a comprehensive test
oracle; preserve package resource inclusion when changing XML assets.
