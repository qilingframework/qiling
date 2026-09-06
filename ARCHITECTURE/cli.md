---
eatmycode_version: "1.1.0"
---

# CLI — qltool and qltui

## Goal

Give users a no-code way to run emulations: `qltool run` executes a binary
against a rootfs, `qltool code` runs shellcode (hex/asm/bin), `qltool
examples` prints usage samples, and `qltool qltui` launches an interactive
TUI that gathers the same options. Owns argument parsing and the mapping
from flags to `Qiling` kwargs; it must not implement emulation behavior.
No roadmap milestone applies; maturity-based status.

## Status

`done` — `tests/test_qltool.py` (observed: `Ran 8 tests … OK` once the
package is installed) shells out to `qltool` for run/code subcommands,
coverage, JSON, and log filtering; `InstalledQltool_Test` checks the
installed console script, shellcode exit status, bundled profiles, and TUI
import outside the checkout.

## Code Structure

| File | Role |
| ---- | ---- |
| `qltool` | Checkout launcher: `from qiling.cli import run` |
| `qiling/cli.py` | Argparse CLI; installed as the `qltool` console script (`pyproject.toml:33-34`); builds kwargs and drives `Qiling` |
| `qltui.py` | questionary/pyfx/termcolor TUI; collects options and returns them to `qltool` |

## Language and Conventions

Python; root rules apply. Enum-valued flags use `__make_enum_arg`
argparse actions mapping lowercase names to `QL_ARCH`/`QL_OS`/`QL_ENDIAN`/
`QL_VERBOSE` (`qiling/cli.py:59-75`). Errors surface as argparse errors or
`Qiling` exceptions; the process exits with `ql.os.exit_code`
(`qiling/cli.py:321`). `qltui.py` is the only module that imports
`questionary`, `pyfx`, and `termcolor` (`pyproject.toml:48-50`).

## Design and Invariants

- Subcommands: `run` (`-f`, `--rootfs`, `--args …`), `code` (`-f`/`-i`,
  `--arch`, `--os`, `--endian`, `--thumb`, `--format asm|hex|bin`),
  `examples`, `qltui` (`qiling/cli.py:196-217`); common flags cover
  verbosity, `--env` (pickled dict), `--gdb`, `--qdb`, `--rr`,
  `--profile`, `--filter`, `--log-file`, `--log-plain`, `--root`,
  `--debug-stop`, `--multithread`, `--timeout`, `--coverage-file`,
  `--coverage-format`, `--json`, `--libcache` (`:225-242`).
- `handle_run`/`handle_code` return the kwargs dict; `Qiling(**ql_args)`
  at `qiling/cli.py:276` is the single construction point, followed by
  optional Qdb (`:279`), gdbserver (`:285`), coverage-wrapped `ql.run()`
  (`:306-310`), JSON report (`:312`), and exit (`:321`).
- `code --format asm` assembles with Keystone via
  `qiling.arch.utils.assembler` (`:104`).
- The installed script and the checkout launcher must behave identically;
  `InstalledQltool_Test` runs with an empty `PYTHONPATH` from a temp
  directory to prove profiles ship in the wheel (`tests/test_qltool.py:55-72`).

## Key Types and Entry Points

- `qiling/cli.py:189` - `run()` - argparse setup and dispatch.
- `qiling/cli.py:129` - `handle_run(options)` - builds
  `{'argv': [file]+args, 'rootfs': …}`.
- `qiling/cli.py:78` - `handle_code(options)` - reads hex/asm/bin shellcode.
- `qiling/cli.py:59` - `__make_enum_arg(enum_rmap, aliases)` - argparse
  action factory.
- `qltui.py` - TUI entry invoked by the `qltui` subcommand.

## Interactions

- Thin client of [core.md](core.md): constructs `Qiling` and calls `run()`.
- Attaches [debugger.md](debugger.md) via `--gdb [HOST:PORT]` /
  `--qdb [--rr]`.
- Uses [extensions.md](extensions.md) for coverage (`cov_utils.factory`)
  and the JSON report.
- Packaging: `pyproject.toml:33-34` defines the console script; the PyPI
  workflow runs `InstalledQltool_Test` against the built wheel
  (`.github/workflows/pythonpublish.yml:41-44`).

## How to Test

```sh
python3 -m pip install -e .
cd tests && python3 test_qltool.py   # pass = "Ran 8 tests … OK", exit 0
```

- `Qltool_Test` uses the checkout launcher `../qltool`;
  `InstalledQltool_Test` needs the console script on the interpreter's
  scripts path (hence the install step). Without it the two installed
  cases error with `FileNotFoundError: …/bin/qltool`.
- Manual smoke test from the repository root (pass = prints
  `Hello, World!`):

  ```sh
  ./qltool run -f examples/rootfs/x8664_linux/bin/x8664_hello --rootfs examples/rootfs/x8664_linux
  ```

## Review and Refactor Guide

- **New flag**: add it to the common or subcommand parser, thread it into
  `ql_args` or the post-construction block, mirror it in `qltui.py`, and
  add a `Qltool_Test` case.
- **Do not** add emulation logic here; new behavior belongs to the owning
  module and is only surfaced by a flag.
- Keep `qltool` (checkout) a two-line launcher so installed and checkout
  behavior cannot diverge.

## Open Gaps / Roadmap

- `qltui.py` has only an import smoke test; its interactive flows are not
  covered.
- Complex setups (fs mappers, custom hooks) still require the Python API.
