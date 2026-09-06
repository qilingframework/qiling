---
eatmycode_version: "1.1.0"
---

# OS Windows family — Windows, UEFI, DOS

## Goal

Emulate API-call-driven (rather than syscall-driven) environments.
Windows: Win32/NT API emulation with handles, registry, fibers, threads,
and PE process structures. UEFI: boot/runtime/SMM services and a protocol
database for DXE/SMM modules. DOS: BIOS/DOS interrupt services for
COM/EXE/MBR targets. No roadmap milestone applies; maturity-based status.

## Status

`done` — UEFI and DOS suites run on Linux (observed: `Ran 2 tests … OK`,
`Ran 1 test … OK`); the Windows PE suite runs in CI on a Windows host with
collected system DLLs and is not runnable from a Linux checkout.

## Code Structure

| File | Role |
| ---- | ---- |
| `qiling/os/windows/windows.py` | `QlOsWindows`: fcall selector, heap, GDT, component setup, `hook_winapi`, run loop |
| `qiling/os/windows/fncc.py`, `api.py` | `@winsdkapi` decorator (cc + typed params) and Windows type aliases over `qiling/os/const.py` |
| `qiling/os/windows/dlls/` | API implementations per DLL (`kernel32/` split by header, `ntdll.py`, `msvcrt.py`, `advapi32.py`, `user32.py`, …) |
| `qiling/os/windows/handle.py`, `registry.py`, `fiber.py`, `thread.py`, `clipboard.py` | Kernel-object emulation: `HandleManager`, `RegistryManager` (python-registry hives), `FiberManager`, `QlWindowsThreadManagement`, `Clipboard` |
| `qiling/os/windows/structs.py`, `const.py`, `wdk_const.py`, `utils.py` | Guest structs and constants (user + WDK) |
| `qiling/os/uefi/uefi.py` | `QlOsUefi` run loop and diagnostics (`emit_context`, `emit_stack`) |
| `qiling/os/uefi/bs.py`, `rt.py`, `ds.py`, `smm.py`, `smst.py`, `st.py`, `protocols/` | Boot/runtime/DXE/SMM service tables and protocol implementations (`@dxeapi`) |
| `qiling/os/uefi/context.py`, `hob.py`, `Uefi*.py`, `type32.py`/`type64.py` | DXE/SMM contexts, HOB list, EDK2-derived type definitions |
| `qiling/os/dos/dos.py`, `interrupts/` | `QlOsDos` flag helpers and `INT 10h/13h/15h/16h/19h/1Ah/20h/21h` handlers |

## Language and Conventions

Python; root rules apply. Local patterns:

- A Windows API is `hook_<Name>(ql, address, params)` decorated with
  `@winsdkapi(cc=STDCALL|CDECL|MS64, params={...})` where param types are
  the aliases in `qiling/os/windows/api.py`; canonical example:
  `qiling/os/windows/dlls/kernel32/fibersapi.py:14-57`. The C prototype
  is kept as a comment above each hook.
- UEFI services use `@dxeapi(params=…)` (`qiling/os/uefi/fncc.py:11`),
  e.g. `qiling/os/uefi/bs.py:23-35`.
- DOS interrupt handlers are plain functions registered in the
  `handlers` map (`qiling/os/dos/interrupts/__init__.py:24`).
- Unimplemented APIs are logged and raise only under `debug_stop`
  (`qiling/os/windows/windows.py:196-199`); implementation errors raise
  `QlErrorSyscallError` (`:189-194`).
- Stub generation for new DLLs: `qiling/extensions/winsdkapi.py` emits
  `@winsdkapi` skeletons from Windows SDK JSON.

## Design and Invariants

- **Dispatch is address-based**: `hook_winapi` runs on every instruction
  (`hook_code`, `qiling/os/windows/windows.py:130`) and matches `address`
  against `ql.loader.import_symbols` filled by the PE loader; user CALL
  overrides in `user_defined_api` win over `dlls/` implementations
  (`:172-186`).
- **Calling conventions**: x86 selects STDCALL/CDECL per API; x86-64 always
  uses MS64 (`:41-65`); `QlOs.call` handles marshalling and the return jump
  ([os-base.md](os-base.md)).
- **Process state** comes from the profile (`[OS32]/[OS64]` heap, `[PATH]`,
  `[USER]`, `[KERNEL]`; `qiling/profiles/windows.ql`) and the PE loader
  (PEB/TEB/LDR); the GDT is set up by the OS
  (`qiling/os/windows/windows.py:132`).
- **Registry** is read from hive files under the rootfs and saved back at
  the end of `run()` (`qiling/os/windows/windows.py:217`).
- **UEFI**: `run()` creates the SMM environment, then executes the loaded
  module chain from the loader (`qiling/os/uefi/uefi.py:202-221`); service
  tables are callable tables installed in guest memory by
  `qiling/os/uefi/st.py`/`smst.py`; variables are managed in `rt.py` with
  known gaps (`qiling/os/uefi/rt.py:204-205`).
- **DOS**: `hook_syscall` installs an interrupt hook that dispatches on
  `(intno, AH)` with ENTER/CALL/EXIT user overrides keyed by that tuple
  (`qiling/os/dos/dos.py:83-107`).
- **Trust boundary**: DLLs, hives, and PE images come from the rootfs; the
  root Review deviations apply to any header-derived size that reaches
  host allocations.

## Key Types and Entry Points

- `qiling/os/windows/windows.py:33` - `QlOsWindows(QlOs)` - `load` (`:125`),
  `__setup_components` (`:156`), `hook_winapi` (`:172`), `run` (`:201`).
- `qiling/os/windows/fncc.py:17` - `winsdkapi(cc, params, passthru)`.
- `qiling/os/windows/handle.py:29` - `HandleManager`; `registry.py:164` -
  `RegistryManager`; `fiber.py:20` - `FiberManager`; `thread.py:94` -
  `QlWindowsThreadManagement`.
- `qiling/os/uefi/uefi.py:22` - `QlOsUefi(QlOs)` - `run` (`:202`),
  `set_api` (`:199`), `save/restore` (`:43`/`:49`).
- `qiling/os/uefi/context.py:12` - `UefiContext` - `DxeContext` (`:80`),
  `SmmContext` (`:87`), protocol database and configuration tables.
- `qiling/os/dos/dos.py:33` - `QlOsDos(QlOs)` - `hook_syscall` (`:83`),
  flag helpers (`:65-80`).
- `qiling/os/os.py:225` - `QlOs.set_api` - user API override by name
  (Windows/UEFI) or `(intno, ah)` tuple (DOS).

## Interactions

- All three subclass [os-base.md](os-base.md) `QlOs`; Windows and UEFI
  allocate from `QlMemoryHeap`.
- [loader.md](loader.md): `QlLoaderPE` builds PEB/TEB and `import_symbols`;
  `QlLoaderPE_UEFI` installs protocols into `qiling/os/uefi/context.py`;
  `QlLoaderDOS` sets real-mode state.
- Argument marshalling uses `QlFunctionCall` with `qiling/cc/intel.py`
  conventions ([arch.md](arch.md)).
- Windows threads subclass `QlThread` ([os-base.md](os-base.md)) and honor
  `QL_HOOK_BLOCK` when switching (`qiling/os/windows/thread.py:120`).
- `examples/uefi_sanitized_heap.py` pairs UEFI with the heap sanitizer from
  [extensions.md](extensions.md); `tests/test_uefi.py:24` proves it.
- [debugger.md](debugger.md): `tests/test_windows_debugger.py` covers GDB
  on PE targets (Windows host).

## How to Test

```sh
cd tests && python3 test_uefi.py && python3 test_dos.py   # pass = "OK" twice, exit 0 (Linux-runnable)
```

- Windows host only: run `examples\scripts\dllscollector.bat` from the
  repository root, then `cd tests && test_pe.bat` (runs `test_pe.py`,
  `test_windows_stdio.py`, `test_peshellcode.py`, `test_windows_debugger.py`,
  `test_dos.py`, `test_pe_sys.py`; CI: `.github/workflows/build-ci.yml:54-62`).
- `tests/test_windows_cpp_x86.py`/`_x8664.py` are not in `test_pe.bat`.

## Review and Refactor Guide

- **Adding a Win32 API**: put `hook_<Name>` in the DLL module matching
  the exporting DLL (`kernel32/` is split by SDK header); use the
  `winsdkapi.py` generator for the signature; add a sample-driven case to
  `tests/test_pe.py`. Coverage is demand-driven (root deviations).
- **Changing `import_symbols` handling** must stay in sync with
  `qiling/loader/pe.py:86`.
- **UEFI protocol additions** go in `qiling/os/uefi/protocols/` and are
  registered through the context's protocol database; test via
  `tests/test_uefi.py` with a sample in the rootfs submodule.
- **DOS interrupts** are added to the `handlers` map with a leaf switch on
  `AH`.
- **Do not** put Windows-only fcall selection in `QlOs`; it lives in
  `QlOsWindows.__init__`.
- Improvement candidates (proposals): implement `QlOs.save/restore` for
  Windows (`TODO.md:663-665`); replace the remaining bare `except:` in
  `qiling/os/windows/registry.py:127` (`TODO.md:628-636`).

## Open Gaps / Roadmap

- Windows tests require a Windows host: system DLLs and hives are not
  redistributable.
- Win32 API surface is demand-driven; fibers, registry, handles, and DLL
  resolution have known gaps (`TODO.md:667-670`).
- UEFI variables ignore namespaces and access attributes
  (`qiling/os/uefi/rt.py:204-205`); SMM covers common protocols only.
