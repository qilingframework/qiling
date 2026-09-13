---
eatmycode_version: "2.0.0"
---

# Executable Loaders

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: changing qiling/loader/, image parsing, relocation, interpreter/library resolution or initial guest state.

## Responsibility and Status

Owns executable parsing/mapping and initial image, stack, entry and import
state for ELF, PE, Mach-O, UEFI PE, DOS, MCU and BLOB. **In progress:** Linux,
UEFI and selected firmware loading were exercised; Windows fixtures and
macOS coverage remain incomplete. Loaders do not own ongoing OS semantics.

## Code Map

| Path / symbol | Role |
| --- | --- |
| [loader.py](../../qiling/loader/loader.py): `QlLoader`, `Image` | Common image ranges, lookup and saved metadata |
| [elf.py](../../qiling/loader/elf.py): `QlLoaderELF` | Segments, interpreter, auxv, initial stack, kernel relocation |
| [pe.py](../../qiling/loader/pe.py): `QlLoaderPE` | PE/DLL imports, exports, relocations, process structures/cache |
| [pe_uefi.py](../../qiling/loader/pe_uefi.py): `QlLoaderPE_UEFI` | DXE/SMM contexts, service tables and module queue |
| [macho.py](../../qiling/loader/macho.py), [macho_parser/](../../qiling/loader/macho_parser/), [dos.py](../../qiling/loader/dos.py), [mcu.py](../../qiling/loader/mcu.py), [blob.py](../../qiling/loader/blob.py) | Other parsers and initialization paths |
| [tests/](../../tests/) `test_elf*.py`, `test_pe*.py`, `test_macho*.py`, `test_uefi.py`, `test_dos*.py`, `test_mcu.py`, `test_blob.py` | Format-specific integration evidence |

## Local Conventions

Use the [root baseline](../../ARCHITECTURE.md#code-conventions); factory class
names are format-derived and include legacy uppercase/camelCase forms.
Keep format-specific logic local. External parser libraries are declared
in the root manifest; MCU Intel HEX parsing and Mach-O helpers are local.
Fixture C/assembly belongs to its behavioral OS owner; preparation to tooling.

## Contracts and Invariants

- Core creates memory and OS before invoking `run`; loaders may initialize
  OS structures and hardware. Preserve entry/exit addresses, image ranges
  and metadata consumed by patches, reports and debuggers (`QlLoader`).
- ELF maps load segments/interpreter and creates guest stack/auxv;
  ELF driver loading uses a separate relocation/import path (`elf.py`).
- PE maps DLLs and records `import_symbols` consumed by Windows dispatch.
  Optional disk caches use pickle (`QlPeCache`); cache contents are trusted
  host artifacts, not safe arbitrary guest inputs.
- UEFI loading creates contexts/heaps/protocols and queues images. Its
  saved state includes selected queue/event members and heap state;
  this does not establish complete firmware snapshot support.
- MCU profile/env declares memory/MMIO/core devices; reset writes firmware
  and initializes CPU context. Raw `.bin` input needs its mapping address;
  HEX parsing implements selected record kinds (`mcu.py`).
- Header-derived addresses/sizes/offsets cross allocation and mapping
  boundaries. Validate changed arithmetic against file bounds and guest
  address width; preserve page alignment and section permissions.

## Dependencies and Boundaries

Read [OS base](os-base.md) for mapping/heap/path contracts; read the changed
format's [POSIX](posix.md), [Windows](windows.md), [UEFI](uefi.md),
[DOS](dos.md) or [bare-metal](baremetal.md) owner when initial state changes.
Read [hardware](hardware.md) for MCU env/MMIO changes, [core](core.md) for
factory/profile changes, [debugger](debugger.md) for image/entry reporting.
OS imports in loaders are intentional construction dependencies.

## Change Guide

| Change trigger | Inspect / extend | Required docs / checks |
| --- | --- | --- |
| Parser/relocation | Format loader, segment/header arithmetic | Format regression plus its OS owner; malformed-input checks for changed validation |
| Stack/import/entry layout | Guest-width structs, profile keys, symbols | Consumer owner and relevant executable/API test |
| Cache/snapshot | Save/restore, cache format and consumers | Core and relevant OS state owner; round-trip evidence |
| Firmware mapping | MCU env/reset or UEFI contexts | Read corresponding firmware/service owners; execution test |

## Verification

From `tests/`: `python -m unittest test_elf.ELFTest.test_elf_linux_x8664 test_blob.BlobTest.test_uboot_arm`
and `python test_uefi.py`. These passed during rebuild with local fixtures.
Use direct UEFI script execution: its test bodies are guarded by `__main__`.
For changed formats, use the corresponding test files in Code Map; Windows
and macOS need their system-library fixtures. Passing ELF does not verify PE.

## Known Gaps

Raw BLOB test requires missing `examples/rootfs/blob/example_raw.bin` in the
examined rootfs; Windows hello tests lacked `Windows/registry` directories.
Mach-O and full PE/kernel-module suites were not verified. Intel HEX handling
is partial; no general malformed-image corpus was found. Treat these as
verification gaps, not supported-input guarantees.
