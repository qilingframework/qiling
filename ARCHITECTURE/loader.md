# Loader — binary format loaders

## Goal

Map the target binary into emulated memory and prepare execution state: parse
the format, load segments/sections and dependencies (ld.so, DLLs, dylibs),
build stack/argv/auxv or OS structures (PEB/TEB, UEFI protocols), and set
entry/exit points. One loader per format, selected by OS type. Mature released
infrastructure; maturity-based status.

## Status

`done` — every format loader is exercised by its OS test suite; the How to
Test command proves the ELF path end-to-end.

## Code Structure

| File | Role |
| ---- | ---- |
| `qiling/loader/loader.py` | Base `QlLoader` + `Image` record; abstract `run()`, save/restore |
| `qiling/loader/elf.py` | ELF for Linux/FreeBSD/QNX: segments, interpreter (ld.so), stack, auxv |
| `qiling/loader/pe.py` | Windows PE: DLL resolution + `QlPeCache`, PEB/TEB/LDR via `Process` |
| `qiling/loader/pe_uefi.py` | UEFI DXE/SMM module loading, protocol installation |
| `qiling/loader/macho.py` | Mach-O (with its own `macho_parser/` package) |
| `qiling/loader/dos.py` | DOS COM/EXE/MBR |
| `qiling/loader/mcu.py` | MCU firmware: Intel HEX (`IhexParser`), ELF, or raw bin per YAML profile |
| `qiling/loader/blob.py` | Raw blobs loaded at a fixed address (e.g. u-boot) |

## Key Types and Entry Points

- `qiling/loader/loader.py:21` - `QlLoader` - base; `Image` NamedTuple (`:15`), abstract `run()` (`:62`), `skip_exit_check` (`:27`).
- `qiling/loader/elf.py:68` - `QlLoaderELF` - loads binary + interpreter, builds stack/auxv (`AUXV` enum `:32`), sets `entry_point`/`elf_entry`.
- `qiling/loader/pe.py:666` - `QlLoaderPE(QlLoader, Process)` - `Process` (`:69`) builds PEB/TEB/LDR; `QlPeCache` (`:41`) caches parsed DLLs behind the `libcache` kwarg (wired in `select_loader`, `qiling/utils.py:300`).
- `qiling/loader/pe_uefi.py:26` - `QlLoaderPE_UEFI` - loads DXE/SMM modules and installs protocols into the UEFI context.
- `qiling/loader/macho.py:70` - `QlLoaderMACHO`.
- `qiling/loader/mcu.py:57` - `QlLoaderMCU` - with `IhexParser` (`:15`).
- OS→loader mapping: `select_loader` (`qiling/utils.py:297`) — LINUX/FREEBSD/QNX→elf, MACOS→macho, WINDOWS→pe, UEFI→pe_uefi, DOS→dos, MCU→mcu, BLOB→blob.

## Interactions

- Instantiated by [core.md](core.md) (`qiling/core.py:183`); `loader.run()` fires at the end of `Qiling.__init__` (`qiling/core.py:195`).
- Uses `ql.mem` ([os-base.md](os-base.md)) for mapping and `ql.arch` ([arch.md](arch.md)) for initial register/stack state.
- The PE loader builds Windows process structures with [os-windows.md](os-windows.md) components (heap, handles); the UEFI loader populates the context in `qiling/os/uefi/`.
- IAT entries recorded here drive address-based API hooking in [os-windows.md](os-windows.md).
- The MCU loader reads the YAML profile owned by [core.md](core.md) and memory maps defined via [hw.md](hw.md).

## How to Test

```sh
cd tests && python3 -m unittest test_elf.ELFTest.test_elf_linux_x8664   # pass = "OK", exit 0
```

- Full loader coverage: `test_elf.py`, `test_pe.py` (Windows host), `test_macho.py` (macOS host), `test_dos.py`, `test_mcu.py`, `test_blob.py`, `test_uefi.py`.

## Open Gaps / Roadmap

- PE and Mach-O loading depend on host-collected libraries (`examples/scripts/dllscollector.bat` / `dylibcollector.sh`); not runnable from a Linux checkout alone.
- `QlPeCache` cache invalidation is manual (delete cache files) — no versioning.
