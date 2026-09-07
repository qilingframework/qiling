---
eatmycode_version: "1.2.0"
---

# Loader — binary format loaders

## Goal

Map the target binary into emulated memory and prepare execution state:
parse the format, load segments/sections and dependencies (ld.so, DLLs,
dylibs), build stack/argv/auxv or OS structures (PEB/TEB, UEFI protocols),
and set entry/exit points. One loader per format, selected by OS type. It
must not implement syscalls or APIs. No roadmap milestone applies;
maturity-based status.

## Status

`done` — every format loader is exercised by its OS suite; the **How to
Test** command proves the ELF path end-to-end (observed: `Ran 1 test … OK`).
PE and Mach-O loading are proven only on their host-gated suites (see
Open Gaps).

## Code Structure

| File | Role |
| ---- | ---- |
| `qiling/loader/loader.py` | Base `QlLoader` + `Image` record; `find_containing_image`, `get_image_by_name`, save/restore, abstract `run()` |
| `qiling/loader/elf.py` | ELF for Linux/FreeBSD/QNX: segments, interpreter, stack/auxv, kernel-module (`.ko`) loading |
| `qiling/loader/pe.py` | Windows PE/driver: DLL resolution, `QlPeCache`, PEB/TEB/LDR via `Process` |
| `qiling/loader/pe_uefi.py` | UEFI DXE/SMM module loading, protocol installation, module chaining |
| `qiling/loader/macho.py` + `macho_parser/` | Mach-O executables and kexts with an in-tree parser |
| `qiling/loader/dos.py` | DOS COM/EXE/MBR (`ComParser`) |
| `qiling/loader/mcu.py` | MCU firmware: Intel HEX (`IhexParser`), ELF, or raw bin; wires peripherals from the profile |
| `qiling/loader/blob.py` | Raw blobs loaded at a fixed address |

## Language and Conventions

Python; root rules apply. Local patterns:

- Loader classes are named `QlLoader<MODULE>` so `select_loader` can derive
  them (`qiling/utils.py:297-320`); the OS→module table lives there.
- Parsing uses `pyelftools`, `pefile`, and the in-tree `macho_parser`;
  segments are mapped through `ql.mem.map` with an `info` label naming the
  image so `QlMemoryManager.get_lib_base` can find it by basename
  (`qiling/os/memory.py:254`).
- The base loader owns `images` and `skip_exit_check`
  (`qiling/loader/loader.py:26-27`); concrete loaders set `entry_point`,
  and the exit point lives on `ql.os`. The ELF loader also sets
  `is_driver` (`qiling/loader/elf.py:121`) and `elf_entry` (`:221`).

## Design and Invariants

- `loader.run()` executes at the end of `Qiling.__init__`
  (`qiling/core.py:195`); it may read `ql.os`, `ql.mem`, `ql.arch`, and the
  profile, but the OS run loop has not started. Loaders sit above the OS
  personalities in import order: they import OS structs, hooks, and API
  tables (`qiling/loader/elf.py:24-27`, `qiling/loader/pe.py:22-26`,
  `qiling/loader/pe_uefi.py:16-24`, `qiling/loader/macho.py:16-25`,
  `qiling/loader/dos.py:12`), and no OS module imports a loader.
- **Shellcode path**: with `code=…` the ELF and PE loaders map a
  shellcode region from profile `[CODE]` values and return early
  (`qiling/loader/elf.py:72-83`, `qiling/os/os.py:90-94`).
- **ELF**: `load_with_ld` (`qiling/loader/elf.py:149`) maps the binary
  and its interpreter and builds the initial stack (argv/envp/auxv per `AUXV`, `:32`);
  `skip_exit_check = (elf_entry != entry_point)` (`:393`) tells core whether
  the exit trap can be written immediately. `ET_REL` inputs are treated as
  kernel modules (`load_driver` `:596`, `lkm_dynlinker` `:440`).
- **PE**: `Process` (`qiling/loader/pe.py:77`) owns PEB/TEB/LDR construction and
  `import_symbols` (address → `{dll, name, ordinal}`), the table the Windows
  API hook consults on every instruction (`qiling/os/windows/windows.py:172`).
  `QlPeCache` (`qiling/loader/pe.py:49`) persists parsed DLL data behind the `libcache`
  kwarg; invalidation is manual.
- **UEFI**: `map_and_load` (`qiling/loader/pe_uefi.py:78`) and
  `execute_module` (`:227`) chain DXE/SMM modules, installing the loaded
  image protocol into a `DxeContext`/`SmmContext`
  (`qiling/os/uefi/context.py:80`, `:87`).
- **MCU**: `run()` (`qiling/loader/mcu.py:135`) merges the YAML profile into
  `ql.env`, then creates peripherals and MMIO regions from every env entry
  (`:127`, `:130`) and hooks Unicorn interrupts to the arch exception
  handler; the loader is the only place hardware gets instantiated.
- **Trust boundary**: every loader parses an untrusted image. Sizes and
  offsets from headers reach `ql.mem.map/write` and `struct` unpacking;
  keep bounds checks at the parse site (see root Review deviations).

## Key Types and Entry Points

- `qiling/loader/loader.py:21` - `QlLoader` - base; `Image` NamedTuple
  (`:15`), `run()` (`:62`), `save/restore` (`:51`/`:58`).
- `qiling/loader/elf.py:68` - `QlLoaderELF` - `run` (`:72`),
  `load_with_ld` (`:149`), `load_driver` (`:596`).
- `qiling/loader/pe.py:821` - `QlLoaderPE(QlLoader, Process)` - `run`
  (`:829`), `load` (`:887`); `Process.load_dll` (`:229`); `QlPeCache` (`:49`).
- `qiling/loader/pe_uefi.py:26` - `QlLoaderPE_UEFI` - `run` (`:370`),
  `map_and_load` (`:78`), `execute_module` (`:227`).
- `qiling/loader/macho.py:70` - `QlLoaderMACHO` - `run` (`:91`).
- `qiling/loader/dos.py:36` - `QlLoaderDOS` - `run` (`:50`); `ComParser` (`:16`).
- `qiling/loader/mcu.py:57` - `QlLoaderMCU` - `run` (`:135`); `IhexParser` (`:15`).
- `qiling/loader/blob.py:10` - `QlLoaderBLOB` - `run` (`:16`).
- `qiling/utils.py:297` - `select_loader(ostype, libcache)` - OS→loader
  mapping (LINUX/FREEBSD/QNX→elf, MACOS→macho, WINDOWS→pe, UEFI→pe_uefi,
  DOS→dos, MCU→mcu, BLOB→blob).

## Interactions

- Instantiated by [core.md](core.md) (`qiling/core.py:183`); `run()` fires
  at `qiling/core.py:195`.
- Uses `ql.mem` ([os-base.md](os-base.md)) for mapping and `ql.arch`
  ([arch.md](arch.md)) for initial register/stack state.
- ELF: [os-posix.md](os-posix.md) `QlOsLinux.run` drives ld.so to
  `elf_entry`, then applies library patches (`qiling/os/linux/linux.py:173-186`);
  kernel modules use `qiling/os/linux/kernel_api/`.
- PE/UEFI: [os-windows.md](os-windows.md) consumes `import_symbols`, heap,
  and handle managers; the UEFI loader populates `qiling/os/uefi/context.py`.
- MCU: reads the YAML profile owned by [core.md](core.md) and calls
  `QlHwManager.setup_mmio/create` ([hw.md](hw.md)).

## How to Test

```sh
cd tests && python3 -m unittest test_elf.ELFTest.test_elf_linux_x8664   # pass = "OK", exit 0
```

- Full ELF coverage: `python3 test_elf.py` (`tests/test_elf.py:30`,
  observed `Ran 53 tests … OK (skipped=2)`); kernel modules:
  `python3 test_elf_ko.py` after unzipping the rootkit fixture (see
  [os-posix.md](os-posix.md)).
- DOS: `python3 test_dos.py`; MCU: `python3 test_mcu.py`; BLOB:
  `python3 -m unittest test_blob.BlobTest.test_uboot_arm`; UEFI:
  `python3 test_uefi.py` (all observed `OK`).
- PE: `tests/test_pe.py` on a Windows host only; Mach-O: `tests/test_macho.py`
  on a macOS host only.

## Review and Refactor Guide

- **Format parsing changes**: keep header-derived sizes bounded before
  they reach `ql.mem`; add a regression sample under `examples/rootfs`
  (submodule) and a case in the owning suite.
- **Changing entry/exit semantics** (`entry_point`, `elf_entry`,
  `skip_exit_check`) affects `Qiling.write_exit_trap`
  (`qiling/core.py:546`) and every OS `run()`; run `tests/test_elf.py`,
  `tests/test_uefi.py`, and `tests/test_mcu.py`.
- **`import_symbols` layout** is a contract with
  `qiling/os/windows/windows.py:172-199`; change both together.
- **Do not** call OS services from loaders beyond heap/handle allocation
  the Windows/UEFI loaders already use; syscalls and APIs belong to the OS
  docs.
- Improvement candidate (proposal): version the `QlPeCache` on-disk format
  so stale caches are detected. Success check: a cache written by an older
  format is rejected and rebuilt in `tests/test_pe.py`.

## Open Gaps / Roadmap

- PE and Mach-O loading depend on host-collected libraries
  (`examples/scripts/dllscollector.bat`, `examples/scripts/dylibcollector.sh`);
  not runnable from a Linux checkout.
- `QlPeCache` invalidation is manual (delete cache files).
- macOS kext loading carries FIXMEs about IOKit providers
  (`qiling/os/macos/macos.py:79-100`).
- `TODO.md:646-649` proposes replacing the label-string search in
  `QlMemoryManager.get_lib_base` (`qiling/os/memory.py:254`), which loaders
  rely on, with a structured mapping.
