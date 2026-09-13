---
eatmycode_version: "2.0.0"
---

# Shared Operating System Services

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: changing qiling/os/*.py, guest memory/heap, filesystem paths/mappings, shared file wrappers or API marshalling.

## Responsibility and Status

Owns shared memory/heap, path virtualization, mapped files/disks, typed
function calls, guest structs, standard streams, statistics and OS base
interfaces. **In progress:** path/struct and integration samples pass;
complete memory/heap/OS-state coverage remains unverified.

## Code Map

| Path / symbol | Role |
| --- | --- |
| [os.py](../../qiling/os/os.py): `QlOs` | Shared streams, profile, API hooks, resolver and call protocol |
| [memory.py](../../qiling/os/memory.py): `QlMemoryManager`, `QlMemoryHeap` | Guest mapping metadata, read/write, MMIO and heap chunks |
| [path.py](../../qiling/os/path.py): `QlOsPath` | Guest path dialect, symlinks, rootfs/host conversion |
| [mapper.py](../../qiling/os/mapper.py): `QlFsMapper`; [filestruct.py](../../qiling/os/filestruct.py), [disk.py](../../qiling/os/disk.py) | Host/file-object bindings, persistent streams and disk helpers |
| [fcall.py](../../qiling/os/fcall.py), [struct.py](../../qiling/os/struct.py), [utils.py](../../qiling/os/utils.py), [stats.py](../../qiling/os/stats.py), [thread.py](../../qiling/os/thread.py), [const.py](../../qiling/os/const.py) | ABI-driven calls, ctypes guest layouts, strings, statistics, shared abstractions |
| [test_pathutils.py](../../tests/test_pathutils.py), [test_struct.py](../../tests/test_struct.py), [test_elf.py](../../tests/test_elf.py) | Path/struct assertions and memory integration |

## Local Conventions

[Root conventions](../../ARCHITECTURE.md#code-conventions) apply. Keep target
width and endian explicit in memory/ctypes helpers; use `ql.mem` for guest
pointers. Function-call helpers preserve existing camelCase methods.
Observed duck typing lets descriptors and mapped objects implement only
needed file operations; do not impose unrelated concrete host types.

## Contracts and Invariants

- Mapping metadata uses sorted non-overlapping half-open ranges, while
  Unicorn's region end is inclusive. Keep metadata and engine mappings in
  sync across map/unmap/protect/restore (`memory.py`). MMIO callbacks receive
  offsets and access widths; heap allocation bookkeeping is separate.
  Mapping labels are compatibility data: `get_lib_base` strips boxed prefixes
  and matches basenames; core library patches depend on this lookup.
- Unmapped filesystem opens resolve a virtual path and check containment
  under rootfs (`QlFsMapper.__open_new`). Explicit mappings deliberately
  bind host paths, factories or objects and bypass this ordinary path.
  Preserve guest Windows/POSIX dialect handling and symlink tests.
- API prototypes preserve parameter order. Resolvers translate strings,
  wide strings and GUID pointers; calling convention owns slots/stack
  unwind. ENTER/EXIT hooks may alter parameters/results (`fcall.py`, `os.py`).
  `QlOs.call` must not write PC after `QL_STATE.STOPPED`; Unicorn can otherwise
  resume despite `emu_stop`. Preserve this guard when changing call returns.
- Standard streams may lack `fileno`; base OS adapts embedded interpreters
  and persistent file wrappers avoid closing host standard descriptors.
- Base `QlOs.save()` returns empty state and `restore()` is a stub. A
  component snapshot must not be assumed to capture host files/resources.
  Keep personality-specific behavior in `QlOs` subclasses; extend shared base
  behavior only when it is a shared contract.

## Dependencies and Boundaries

Read [arch](arch.md) for ABI/width changes, the consuming OS owner for paths,
errno/API semantics, [loaders](loaders.md) for mapped layout/labels, [core](core.md) for library-patch lookup, and
[hardware](hardware.md) for MMIO. Read [kernel proxy](kernel-proxy.md) when
changing descriptor operations that proxy-owned objects must implement.
Host opens, ctypes and string reads are trust boundaries; guest values need
validation at the operation that consumes them.

## Change Guide

| Change trigger | Inspect / extend | Required docs / checks |
| --- | --- | --- |
| Paths/mapping | Dialect conversion, symlink containment, explicit bindings | Path tests plus consuming OS filesystem case |
| Memory/heap/MMIO | Range convention, engine metadata, allocator state | ELF memory search; MCU snapshot for MMIO state |
| Struct/call/strings | Target packing, slots, resolvers, unwind | Struct tests; arch plus API consumer tests |
| Descriptor/disk | Wrapper methods, lifetime/dup and host errors | POSIX or DOS owner; proxy owner if fd polymorphism changes |

## Verification

Use root's shared-primitives command from `tests/`: it ran 21 cases: 16 passed,
5 explicitly skipped (host-specific path behavior and wchar cases).
`python -m unittest test_elf.ELFTest.test_memory_search` also passed.
Root dependencies and ELF rootfs fixture are needed for integration.
These do not prove memory-manager/heap coverage; changed allocator or call
semantics need their own existing consumer regression extended as appropriate.

## Known Gaps

Four wchar struct cases are marked broken/skipped in `test_struct.py`.
`os/utils.py` string readers do not establish a global maximum guest-string
length. Base OS save/restore is partial by design. There is no dedicated
exhaustive memory/heap/fcall test suite; proposals in `TODO.md` must retain
behavior and gain focused evidence before implementation claims.
