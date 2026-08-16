# CLI — qltool and qltui

## Goal

Give users a no-code way to run emulations: `qltool run` executes a binary
against a rootfs, `qltool code` runs shellcode (hex/asm/bin), `qltool
examples` prints usage samples, and `qltool qltui` launches an interactive
TUI that gathers the same options. Mature released infrastructure;
maturity-based status.

## Status

`done` — covered by `tests/test_qltool.py`, which shells out to `qltool` for
run/code subcommands including gdb attach and coverage output.

## Code Structure

| File | Role |
| ---- | ---- |
| `qltool` | Executable argparse CLI; builds kwargs and drives `Qiling` |
| `qltui.py` | questionary/pyfx/termcolor TUI; collects options, returned to qltool |

## Key Types and Entry Points

- `qltool:189` - `run()` - argparse setup with subcommands `run`, `code`, `examples`, `qltui`; enum-mapping actions translate `--arch/--os/--endian/--verbose` strings to `QL_ARCH`/`QL_OS` enums (`qltool:59-75`).
- `qltool:129` - `handle_run(options)` - builds `{'argv': [file]+args, 'rootfs': ...}`.
- `qltool:78` - `handle_code(options)` - reads hex/asm/bin shellcode, assembling asm via `qiling.arch.utils.assembler` (`qltool:104`).
- `qltool:276` - `ql = Qiling(**ql_args)` - the single construction point; then optional Qdb (`:279`), gdbserver (`:285`), coverage-wrapped `ql.run()` (`:306-310`), JSON report (`:312`), exit with `ql.os.exit_code` (`:321`).

## Interactions

- Thin client of [core.md](core.md): constructs `Qiling` and calls `run()`.
- Attaches [debugger.md](debugger.md) via `--gdb host:port` / `--qdb [--rr]`.
- Uses [extensions.md](extensions.md) for `--coverage-file` (drcov) and `--json` report output.
- `qltool examples` mirrors scripts documented in `examples/README.md`.

## How to Test

```sh
cd tests && python3 test_qltool.py   # pass = unittest "OK", exit 0
```

- Manual smoke test: `./qltool run -f examples/rootfs/x8664_linux/bin/x8664_hello --rootfs examples/rootfs/x8664_linux` — pass = prints `Hello, World!`.

## Open Gaps / Roadmap

- `qltui.py` (TUI) has no automated tests — interactive only.
- `qltool` predates subcommand-style config files; complex setups (fs mappers, custom hooks) still require the Python API.
