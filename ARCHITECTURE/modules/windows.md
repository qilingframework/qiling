---
eatmycode_version: "2.1.0"
---

# Windows API Emulation

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: changing qiling/os/windows/, Win32/NT APIs, handles, registry, fibers or guest thread/process state.

## Responsibility and Status

Owns Win32/NT API emulation, process environment, handles, registry,
clipboard, fibers and guest thread management. **In progress:** source is
implemented but PE hello verification is blocked by missing registry
fixtures; comprehensive Windows behavior is unverified. PE parsing belongs
to loaders; UEFI and DOS have separate owners.

## Code Map

| Path / symbol | Role |
| --- | --- |
| [windows.py](../../qiling/os/windows/windows.py): `QlOsWindows` | Process setup, API dispatch and execution |
| [fncc.py](../../qiling/os/windows/fncc.py): `winsdkapi` | API prototype/CC decorator and ENTER/EXIT hooks |
| [dlls/](../../qiling/os/windows/dlls/), [api.py](../../qiling/os/windows/api.py) | DLL hook implementations and exported namespace |
| [handle.py](../../qiling/os/windows/handle.py): `HandleManager`; [registry.py](../../qiling/os/windows/registry.py): `RegistryManager` | Guest object IDs and hive/overlay state |
| [thread.py](../../qiling/os/windows/thread.py), [fiber.py](../../qiling/os/windows/fiber.py), [structs.py](../../qiling/os/windows/structs.py), [wdk_const.py](../../qiling/os/windows/wdk_const.py) | Scheduling, guest layouts and driver constants |
| [test_pe.py](../../tests/test_pe.py), [test_pe_sys.py](../../tests/test_pe_sys.py), [test_peshellcode.py](../../tests/test_peshellcode.py), [tests/](../../tests/) `test_windows*.py`; [examples/src/windows/](../../examples/src/windows/) | User/kernel/shellcode and C/C++ fixtures |

## Local Conventions

Use the [root baseline](../../ARCHITECTURE.md#code-conventions).
`hook_<API>` functions use `@winsdkapi(cc=..., params=...)`, then receive
`(ql, address, params)` via the wrapper. Preserve Windows API capitalization,
A/W variants and target-width typedefs. Extend the owning DLL file/API export
path; the SDK stub helper is owned by extensions and is not an authoritative
implementation. No universal Windows fixture compiler version is declared.

## Contracts and Invariants

- `hook_winapi` recognizes addresses in loader `import_symbols`, resolves
  names/ordinals and user CALL hooks, then built-in hooks. Missing APIs warn
  or fail under `debug_stop`; implementation exceptions become
  `QlErrorSyscallError` (`windows.py`).
- `winsdkapi` selects calling convention and delegates decoding, ENTER/EXIT
  hooks and unwind to shared OS/fcall. Stack cleanup and return width must
  match x86 versus x64; API success/error conventions remain API-specific.
- Handles are guest identities around host/Python objects, not native
  Windows handles. Registry hives come from rootfs; the manager persists
  its overlay after normal `run()` completion. Maintain host-file/path
  boundaries when adding APIs.
- Process PEB/TEB, segment bases and thread contexts couple this module to
  PE initialization and architecture utilities. Base OS save/restore does
  not capture the entire Windows environment.

## Dependencies and Boundaries

Read [loaders](loaders.md) when import symbols or process structures change,
[OS base](os-base.md) for pointers, paths and fcall, [arch](arch.md) for
calling conventions and segments, [debugger](debugger.md) for breakpoints.
Win32 hook behavior should stay within this owner; do not move it into
shared dispatch just to support one DLL or driver.

## Change Guide

| Change trigger | Inspect / extend | Required docs / checks |
| --- | --- | --- |
| DLL/API handler | Decorator prototype, export, A/W and error handling | Matching PE/API test; OS base if marshalling changes |
| Handle/registry/thread state | Ownership/lifetime, guest structs, persistence | Existing Windows regression + PE initialization case |
| Driver API or shellcode | WDK structures, loader path and CC | `test_pe_sys.py` or `test_peshellcode.py`; loader/arch owners |

## Verification

From `tests/`: `python -m unittest test_pe.PETest.test_pe_win_x86_hello test_pe.PETest.test_pe_win_x8664_hello`.
Both were attempted and failed before emulation because the matching rootfs
`Windows/registry` directory is absent (`registry.py`). These are blocked
checks, not passing evidence. With complete system libraries/registry
fixtures, use the matching Windows scripts and `test_pe.bat` under its
Windows CI prerequisites. See [tooling](cli-build.md) for fixture preparation.

## Known Gaps

Full Windows verification requires collected system libraries and registry
fixtures; Linux checks do not substitute for the Windows CI job. API
coverage is demand-driven and includes stubs; inspect the target hook before
claiming support. Complete OS snapshots and all guest threading semantics
remain unverified.
