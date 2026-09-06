# CLI — qltool and qltui

## Goal

Give users a no-code way to run emulations: `qltool run` executes a binary
against a rootfs, `qltool code` runs shellcode (hex/asm/bin), `qltool
examples` prints usage samples, and `qltool qltui` launches an interactive
TUI that gathers the same options. Mature released infrastructure;
maturity-based status.

## Status

`done` — covered by `tests/test_qltool.py`, which shells out to `qltool` for
run/code subcommands and coverage output. `InstalledQltool_Test` checks the
installed command, shellcode exit status, bundled profiles, and TUI import
outside the checkout.

## Code Structure

| File | Role |
| ---- | ---- |
| `qltool` | Checkout launcher for `qiling.cli.run` |
| `qiling/cli.py` | Argparse CLI; installed as `qltool`, builds kwargs and drives `Qiling` |
| `qltui.py` | questionary/pyfx/termcolor TUI; collects options, returned to qltool |

## Key Types and Entry Points

- `qiling/cli.py:189` - `run()` - argparse setup with subcommands `run`, `code`, `examples`, `qltui`; enum-mapping actions translate `--arch/--os/--endian/--verbose` strings to `QL_ARCH`/`QL_OS` enums (`qiling/cli.py:59-75`).
- `qiling/cli.py:129` - `handle_run(options)` - builds `{'argv': [file]+args, 'rootfs': ...}`.
- `qiling/cli.py:78` - `handle_code(options)` - reads hex/asm/bin shellcode, assembling asm via `qiling.arch.utils.assembler` (`qiling/cli.py:104`).
- `qiling/cli.py:276` - `ql = Qiling(**ql_args)` - the single construction point; then optional Qdb (`:279`), gdbserver (`:285`), coverage-wrapped `ql.run()` (`:306-310`), JSON report (`:312`), exit with `ql.os.exit_code` (`:321`).

## Interactions

- Thin client of [core.md](core.md): constructs `Qiling` and calls `run()`.
- Attaches [debugger.md](debugger.md) via `--gdb host:port` / `--qdb [--rr]`.
- Uses [extensions.md](extensions.md) for `--coverage-file` (drcov) and `--json` report output.
- `qltool examples` mirrors scripts documented in `examples/README.md`.

## How to Test

```sh
python3 -m pip install .
cd tests && python3 test_qltool.py   # pass = unittest "OK", exit 0
```

- Packaging regression checks, from the repository root after installing
  the built wheel: `python3 -I tests/test_qltool.py InstalledQltool_Test -v`.
- Manual smoke test: `./qltool run -f examples/rootfs/x8664_linux/bin/x8664_hello --rootfs examples/rootfs/x8664_linux` — pass = prints `Hello, World!`.

## Open Gaps / Roadmap

- `qltui.py` has an installed import smoke test; its interactive flows are
  not covered by automated tests.
- `qltool` predates subcommand-style config files; complex setups (fs mappers, custom hooks) still require the Python API.
