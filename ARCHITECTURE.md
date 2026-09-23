---
eatmycode_version: "2.1.0"
---

# Qiling Architecture

Generated with [eatmycode](https://github.com/xwings/eatmycode).

## Read First

Before planning code changes or reviewing code, read
[Agent Rules](ARCHITECTURE/AGENT_RULES.md). Follow the Task Index to the
owning module and read pages whose **Read when** trigger matches the task.
Load partner modules only for affected boundaries; never load the entire
ARCHITECTURE directory. Reuse unchanged pages already read in this session.
Check claims against source, configuration, and tests; they remain
authoritative. If a route or fact is missing or stale, inspect source and
repair the affected docs. For broad changes, work through owners in batches
and retain cross-owner constraints and verification evidence.

## Project Snapshot

| Fact | Value and evidence |
| --- | --- |
| Purpose | Binary emulation over Unicorn with images, OS APIs, hooks and firmware; entry is `Qiling(...).run()` ([core](qiling/core.py)). Complete OS/device fidelity is outside implemented scope. |
| Language / package | Python `^3.10`; package `1.4.12.dev0`, GPL-2.0-or-later; Poetry backend `poetry-core>=2.0,<3.0` ([manifest](pyproject.toml)). Fixture C/C++/assembly toolchains are local. |
| Engines | Unicorn **2.1.3**, Capstone `^5`, Keystone `^0.9.2`; other dependencies/platform extras in the manifest and [lock](poetry.lock). |
| Compatibility | Arch/OS enums in [const.py](qiling/const.py), composition in [utils.py](qiling/utils.py); enums do not promise every combination. [CI](.github/workflows/build-ci.yml) declares Python 3.11/3.13 on Ubuntu/Windows; macOS job is commented out. |

## System Design

`Qiling.__init__` composes arch → hooks/packing → logging/profile → loader →
memory → OS → optional hardware, then runs the loader. `run()` applies
patches and delegates to the OS loop; Unicorn hooks enter Python dispatch.
Arch owns CPU/register state, memory owns mappings, loaders own image state,
and OS personalities own process/API state. Factory names are compatibility
contracts ([core](qiling/core.py), [factories](qiling/utils.py)).

Guest bytes/pointers cross host boundaries through loaders, memory, files
and sockets. Rootfs handling is not complete
host isolation; explicit mappings expose host objects. Snapshot files use
pickle and require trusted producers. The opt-in kernel proxy executes real
host syscalls. Follow the owners below for these contracts. Cooperative
scheduling and partial snapshots do not provide complete machine recovery.

## Code Conventions

- **Required:** [.editorconfig](.editorconfig) sets Python UTF-8, LF, four
  spaces, final newline and trailing-space removal. No formatter, linter or
  type-checker gate is configured in the manifest/CI.
- **Observed:** `Ql*` classes, snake_case helpers, uppercase constants;
  legacy camelCase APIs and wildcard imports remain. Follow nearby code,
  preserve public names, use `ql.log` and `QlError*` where established;
  annotations are mixed ([core](qiling/core.py), [errors](qiling/exception.py)).
- **Preserved project rules:** favor platform fidelity, keep API/peripheral
  additions demand-driven, and treat Unicorn upgrades as project-wide work.
  New top-level runtime dependencies require an explicit request; optional
  integrations use extras. These strengthen shared review (prior project
  architecture; current [manifest](pyproject.toml)). Keep dependencies toward
  underlying services; read [core](ARCHITECTURE/modules/core.md) before
  changing cross-layer imports for the existing exceptions.
- `AGENT.md` and `CLAUDE.md` alias this page; asset/fixture edit constraints
  live with owners.

## Verification

| Change/check | Command and working directory | Prerequisites / pass evidence |
| --- | --- | --- |
| Setup | `python3 -m venv .venv`; activate it; `python -m pip install -e .` — root | Python in declared range; engine wheels/build prerequisites. |
| Local CLI | `python qltool --help` — root | Installed dependencies; help exits zero. |
| Shared primitives | `python -m unittest test_pathutils test_struct` — `tests/` | Passing assertions; no full emulation claim. |
| Runtime changes | Owner commands below; Linux aggregate `./test_onlinux.sh` — `tests/` | [Rootfs submodule](.gitmodules), test-specific libraries/hosts; aggregate stops on first failure. |
| Build / metadata | [CLI and build checks](ARCHITECTURE/modules/cli-build.md#verification) for packaging/config changes | Mirrors [package CI](.github/workflows/pythonpublish.yml); lint/type checks unavailable. |

## Task Index

| Source paths / task trigger | Responsibility | Read next |
| --- | --- | --- |
| `qiling/{core*,utils,const,exception,host,log,__init__}.py`, `arch/`, `cc/`, `loader/`, `profiles/`; composition, CPU, images | Runtime and loading | [Runtime routes](ARCHITECTURE/indexes/runtime.md) |
| `qiling/os/` shared files, `posix/` except `kernel_proxy/`, `linux/`, `freebsd/`, `macos/`, `qnx/`, `windows/`, `uefi/`, `dos/`; OS behavior | Services and personalities | [OS routes](ARCHITECTURE/indexes/operating-systems.md) |
| `qiling/os/{mcu,blob}/`, `hw/`, `extensions/{mcu/,multitask.py}`; firmware/devices | Firmware and MMIO | [Firmware routes](ARCHITECTURE/indexes/firmware.md) |
| `qiling/os/posix/kernel_proxy/`, hybrid-kernel sections of `TODO.md`, `tests/test_kernel_proxy.py`; forwarding | Host-kernel integration | [Kernel proxy](ARCHITECTURE/modules/kernel-proxy.md) |
| `qiling/debugger/`, `tests/test_*debugger.py`, `test_qdb.py`, `qdb_scripts/`; debugging | GDB and Qdb | [Debugger](ARCHITECTURE/modules/debugger.md) |
| Other `qiling/extensions/`, `examples/fuzzing/`, `tests/test_{history,r2}.py`; integrations | Instrumentation | [Extensions](ARCHITECTURE/modules/extensions.md) |
| `qiling/cli.py`, `qltool`, `qltui.py`, manifests/lock, `Dockerfile`, `.github/`, test drivers, `.gitmodules`; tooling | CLI and development checks | [CLI and build](ARCHITECTURE/modules/cli-build.md) |
