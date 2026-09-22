---
eatmycode_version: "2.0.0"
---

# CLI, Packaging and Development Tooling

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: changing qiling/cli.py, qltool, qltui.py, manifests/lock, Dockerfile, CI/test drivers or fixture preparation.

## Responsibility and Status

Owns CLI/TUI entry behavior, package/resources, build and test wiring, and
fixture preparation mechanics. **In progress:** selected checkout CLI tests,
fresh installed-wheel smoke and sdist/wheel build pass; full interactive
TUI, container and host CI matrices remain unverified. Guest behavior in
examples/tests belongs to its runtime owner.

## Code Map

| Path / symbol | Role |
| --- | --- |
| [qiling/cli.py](../../qiling/cli.py): `run`, `handle_run`, `handle_code` | Argument parsing, input conversion, emulation and output options |
| [qltool](../../qltool), [qltui.py](../../qltui.py): `get_data` | Checkout launcher and interactive front end |
| [pyproject.toml](../../pyproject.toml), [poetry.lock](../../poetry.lock) | Package/dependencies/extras, console entry and reproducible resolution |
| [.github/workflows/](../../.github/workflows/), [Dockerfile](../../Dockerfile), [.editorconfig](../../.editorconfig) | Build/test environment and source-format baseline |
| [test_qltool.py](../../tests/test_qltool.py): `InstalledQltool_Test`; [test_onlinux.sh](../../tests/test_onlinux.sh), [test_pe.bat](../../tests/test_pe.bat), [test_macho.sh](../../tests/test_macho.sh) | CLI contracts, installed package smoke and platform test drivers; `test_perf.py`/`view_perf_results.py` profile existing suites |
| [.gitmodules](../../.gitmodules), [examples/scripts/](../../examples/scripts/), [examples/src/](../../examples/src/), [README.md](../../README.md), [docs/](../../docs/) | External fixtures, collectors/build inputs and existing user-facing documentation |

## Local Conventions

Use the [root baseline](../../ARCHITECTURE.md#code-conventions).
`argparse` actions convert enum/environment inputs and build `Qiling` keyword
arguments. Preserve option names and exit status. TUI uses questionary/termcolor; its
interactive report viewer imports `fx` lazily and ships in the `tui`
extra; testing its import is not testing its prompts. Keep build metadata
in the manifest, resolve its lock with Poetry, and retain package license
and resource attribution. Documentation here contains coding context only.

## Contracts and Invariants

- Checkout `qltool` and installed console entry call `qiling.cli:run`.
  Wheel must include `qltui.py`, profiles and debugger XML; checkout-only
  relative imports/paths must not be required by installed execution.
- CLI/TUI environment input uses `pickle.load` when the argument names an
  existing file, and `literal_eval` otherwise (`cli.py:__arg_env`,
  `qltui.py:env_arg`). Pickle files require trusted producers; neither path
  establishes a dictionary-schema validation guarantee.
- Package version comes from distribution metadata with an uninstalled
  fallback in `qiling/__init__.py`; manifest, lock and CLI tests must agree.
- Native engine pins and platform-marked extras are compatibility inputs.
  Container uses Python 3.13 slim with build tools in a separate stage;
  container success is a separate check from wheel validation.
- Test paths commonly assume `tests/` as cwd. Rootfs is an external Git
  submodule; fixtures may need system libraries or extracted archives.
  Keep user changes and fixture revision separate from source edits.
- C/C++/assembly fixtures have local Makefiles and cross-toolchains. Change
  fixture source with its behavioral owner; do not silently replace a
  binary/submodule pin to hide a failing assertion. Ignored `jexamples/`
  is local scratch, not a declared shipped package or required CI suite.

## Dependencies and Boundaries

Read [core](core.md) for options/run configuration, [debugger](debugger.md)
for debugger flags and [extensions](extensions.md) for coverage/reporting.
Fixture preparation is tooling ownership; test assertions and guest payload
semantics route to their OS/CPU/device owner. Workflow publishing steps are
outside architecture's coding scope; package build/test contracts remain here.

## Change Guide

| Change trigger | Inspect / extend | Required docs / checks |
| --- | --- | --- |
| CLI/TUI option | Parser, argument mapping, exit/result | Checkout CLI case; affected runtime owner; installed smoke for public entry |
| Dependency/resource/build | Manifest/lock, wheel contents, workflow | Metadata/build/installed checks below; relevant engine owner |
| CI/fixture setup | Platform driver, rootfs/version, collectors | Run applicable host suite or record missing prerequisite; behavioral owner |

## Verification

**Shared test-resource rule (preserved):** serialize suites sharing fixed
localhost ports or fixtures; do not run aggregates beside their constituents.
`test_posix.py` imports ELF/CLI cases, ELF uses port 8000, debugger tests use
fixed ports including 9999, and `test_onlinux.sh` runs scripts sequentially.

From root after setup, with Poetry 2, build and Twine installed:

```sh
poetry check --lock
python -m build
python -m twine check --strict dist/*
```

Install the resulting wheel in a fresh virtual environment, then from root:
`python -I tests/test_qltool.py InstalledQltool_Test -v`. Three tests run
CLI/version/profile behavior and TUI import outside the checkout. For
checkout behavior from `tests/`: `python test_qltool.py`; rootfs samples
are required for argument, JSON, filter and coverage cases.

Rebuild evidence: sdist plus wheel-from-sdist build passed, artifact metadata
checks and `poetry check --lock` passed, 8 selected CLI tests passed, and 3 installed-wheel cases
passed in a second fresh environment. See [root verification](../../ARCHITECTURE.md#verification)
for common setup and Linux aggregate. No configured lint/type-check command exists.

## Known Gaps

Full Windows/macOS fixtures, raw BLOB sample and complete host matrix were
not available/verified. `.github/workflows/build-ci.yml` uses
`matrix.contrainer` instead of `matrix.container`, so the intended container
branch lacks reliable coverage. Interactive TUI, fixture rebuilds and Docker
image build were not exercised. Build success alone does not certify guest
execution or all optional integrations.
