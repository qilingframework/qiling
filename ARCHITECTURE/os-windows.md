# OS Windows family — Windows, UEFI, DOS

## Goal

Emulate API-call-driven (rather than syscall-driven) environments. Windows:
Win32/NT API emulation with handles, registry, and PE process structures.
UEFI: boot/runtime/SMM services and protocol database for DXE/SMM modules.
DOS: BIOS/DOS interrupt services for COM/EXE/MBR targets. Mature released
infrastructure; maturity-based status.

## Status

`done` — Windows PE suite runs in CI on a Windows host; UEFI and DOS suites
run on Linux. Windows tests are platform-gated locally (need collected DLLs).

## Code Structure

| File | Role |
| ---- | ---- |
| `qiling/os/windows/windows.py` | `QlOsWindows`: component setup (handles, registry, clipboard, fiber), run loop |
| `qiling/os/windows/dlls/` | Win32 API implementations per DLL (kernel32/, ntdll.py, msvcrt.py, advapi32.py, …) |
| `qiling/os/windows/fncc.py`, `api.py` | Decorators declaring API signatures/calling conventions |
| `qiling/os/windows/handle.py`, `registry.py`, `clipboard.py`, `fiber.py`, `thread.py`, `structs.py` | Windows kernel-object emulation |
| `qiling/os/uefi/uefi.py` | `QlOsUefi` run loop |
| `qiling/os/uefi/bs.py`, `rt.py`, `ds.py`, `smm.py`, `protocols/` | Boot/runtime/DXE/SMM services and protocol implementations |
| `qiling/os/uefi/context.py` | UEFI execution contexts populated by the loader |
| `qiling/os/dos/dos.py` | `QlOsDos` run loop |
| `qiling/os/dos/interrupts/` | INT 10h/13h/15h/16h/21h… service handlers |

## Key Types and Entry Points

- `qiling/os/windows/windows.py:33` - `QlOsWindows(QlOs)` - `__setup_components` (`:156`) builds handle manager/registry/clipboard/fiber; `run()` (`:201`).
- `qiling/os/windows/fncc.py` - `@winsdkapi` decorator - declares an API's calling convention and typed params; implementations live in `dlls/`.
- API dispatch is address-based: IAT addresses recorded by the PE loader are hooked and marshalled through `QlFunctionCall` — user overrides via `QlOs.set_api` (`qiling/os/os.py:225`).
- `qiling/os/uefi/uefi.py:22` - `QlOsUefi(QlOs)` - executes DXE/SMM modules; services in `bs.py`/`rt.py`/`smm.py` are installed as callable tables.
- `qiling/os/dos/dos.py:33` - `QlOsDos(QlOs)` - dispatches BIOS/DOS interrupts from `interrupts/`.

## Interactions

- All three subclass [os-base.md](os-base.md) `QlOs` and allocate from `QlMemoryHeap`.
- [loader.md](loader.md): `QlLoaderPE` builds PEB/TEB and records IAT hook addresses; `QlLoaderPE_UEFI` installs protocols into `qiling/os/uefi/context.py`; `QlLoaderDOS` sets real-mode state.
- Argument marshalling uses `QlFunctionCall` + `qiling/cc/intel.py` conventions ([arch.md](arch.md)).
- The registry emulation reads hive files from the rootfs via [os-base.md](os-base.md) path services.
- `examples/uefi_sanitized_heap.py` pairs UEFI with the heap sanitizer from [extensions.md](extensions.md).

## How to Test

```sh
cd tests && python3 test_uefi.py   # pass = unittest "OK", exit 0 (Linux-runnable)
```

- Windows host only: `cd tests && cmd.exe /C test_pe.bat` after running `examples/scripts/dllscollector.bat` (CI does this in `.github/workflows/build-ci.yml`).
- DOS: `cd tests && python3 test_dos.py` (uses scripted keyboard input).

## Open Gaps / Roadmap

- Windows tests require a Windows host: system DLLs/registry hives are not redistributable and must be collected locally.
- Win32 API surface is demand-driven; unimplemented APIs raise `QlErrorSyscallNotFound`-style errors and are added as samples need them.
- SMM emulation covers common protocols only (see `qiling/os/uefi/smm.py`).
