---
eatmycode_version: "1.2.0"
---

# OS base — shared OS-layer services

## Goal

Own the OS-agnostic services every OS personality builds on: the abstract
`QlOs` class, the emulated memory manager and heap, function-call argument
marshalling over calling conventions, filesystem virtualization (rootfs
confinement plus host mapping), file-descriptor objects, green-thread base,
struct helpers, and API-call statistics. It must not contain syscall or API
implementations. No roadmap milestone applies; maturity-based status.

## Status

`done` — path virtualization and struct helpers have dedicated unit tests
(observed: `Ran 3 tests … OK (skipped=1)` and `Ran 18 tests … OK (skipped=4)`);
everything else is exercised by every OS suite.

## Code Structure

| File | Role |
| ---- | ---- |
| `qiling/os/os.py` | Abstract `QlOs`: stdio, path/fs-mapper composition, `user_defined_api`, `call`, `set_api`, abstract `run()`, `emu_error` |
| `qiling/os/memory.py` | `QlMemoryManager` (`ql.mem`: map/unmap/protect/search/MMIO) and `QlMemoryHeap` |
| `qiling/os/fcall.py` | `QlFunctionCall`: read args / write retval using `qiling/cc/` conventions |
| `qiling/os/mapper.py` | `QlFsMapper` / `QlFsMappedObject`: redirect emulated paths to host files or Python objects |
| `qiling/os/path.py` | `QlOsPath`: rootfs confinement and virtual↔host path conversion |
| `qiling/os/filestruct.py`, `disk.py` | `ql_file`/`PersistentQlFile` fd objects and raw-disk mapped object |
| `qiling/os/thread.py` | `QlThread(Greenlet)` base for multithread emulation |
| `qiling/os/stats.py` | `QlOsStats` / `QlWinStats`: API and syscall call statistics |
| `qiling/os/struct.py` | `BaseStruct` and the `get_packed_struct` / `get_aligned_struct` factories |
| `qiling/os/utils.py`, `const.py` | `QlOsUtils` (string readers, `print_function`), fcall parameter type constants |

## Language and Conventions

Python; root rules apply. Local patterns:

- Guest-facing structures are `ctypes` classes built through
  `get_packed_struct`/`get_aligned_struct` (`qiling/os/struct.py:226`,
  `:246`) so endianness and pointer width follow the target; canonical use:
  `qiling/os/posix/syscall/epoll.py:31-45`.
- API parameter types are the `PARAM_*`/`STRING`/`WSTRING`/`GUID`
  constants in `qiling/os/const.py:9-32`; resolvers turn pointers into
  Python values (`qiling/os/os.py:96-104`).
- Errors: `QlErrorNotImplemented`, `QlMemoryMappedError`, `QlOutOfMemory`
  from `qiling/exception.py`. `assert` is used for page-size and alignment
  checks in `qiling/os/memory.py:65`, `:281`, `:303`; `TODO.md:638-644`
  flags this as observed, not a convention.
- Logging goes through `ql.log`; `QlOsUtils.print_function`
  (`qiling/os/utils.py:106`) is the single formatter for syscall/API log
  lines.

## Design and Invariants

- **Construction order**: `QlMemoryManager` is created before the OS
  (`qiling/core.py:188-189`); `QlOs.__init__` reads the profile, builds
  `QlOsPath`/`QlFsMapper` only for POSIX, Windows, and DOS
  (`qiling/os/os.py:44-49`), and sets a bit-width default exit point
  (`:82-87`).
- **Rootfs confinement**: every guest path resolves through `QlOsPath`;
  `__is_safe_host_path` canonicalizes and requires the result to stay under
  the rootfs (`qiling/os/path.py:239-266`). `QlFsMapper` overrides win only
  for explicitly mapped virtual paths (`qiling/os/mapper.py:189`). This is
  the host trust boundary named in the root Review deviations;
  `tests/test_pathutils.py` enforces it.
- **API call protocol**: `QlOs.call` (`qiling/os/os.py:198`) resolves
  params via the current `fcall`, invokes the handler with `onenter/onexit`
  hooks from `user_defined_api`, logs, records stats, and sets `pc` to the
  return address unless emulation already stopped (`:215-221`).
- **Memory manager owns `map_info`**; all mapping goes through
  `map`/`map_mmio`/`unmap`/`protect` (`qiling/os/memory.py:622`, `:644`,
  `:451`, `:612`). MMIO regions are Unicorn callbacks bound to a
  `QlMmioHandler` (`:17`).
- **Heap**: `QlMemoryHeap` (`:678`) is a simple chunk allocator used by
  Windows/UEFI APIs; the sanitizer extension wraps it.
- **Threads**: `QlThread` is a gevent `Greenlet` (`qiling/os/thread.py:11`);
  cooperative scheduling only.
- `QlOs.save/restore` are empty in the base (`qiling/os/os.py:106-109`);
  personalities that support snapshots override them.

## Key Types and Entry Points

- `qiling/os/os.py:24` - `QlOs` - `__init__` (`:29`), `call` (`:198`),
  `set_api` (`:225`), abstract `run()` (`:240`), `stop` (`:243`),
  `emu_error` (`:249`).
- `qiling/os/memory.py:40` - `QlMemoryManager` - `map` (`:622`),
  `map_mmio` (`:644`), `read/write` (`:349`/`:383`), `read_ptr/write_ptr`
  (`:361`/`:393`), `search` (`:414`), `find_free_space` (`:540`),
  `get_lib_base` (`:254`).
- `qiling/os/memory.py:678` - `QlMemoryHeap` - `alloc` (`:721`), `free`
  (`:771`), `size` (`:757`).
- `qiling/os/fcall.py:21` - `QlFunctionCall(ql, cc, accessors)` - argument
  and return-value marshalling over `qiling/cc/`.
- `qiling/os/mapper.py:64` - `QlFsMapper` - behind `Qiling.add_fs_mapper`
  (`qiling/core.py:701`); `open_ql_file` (`qiling/os/mapper.py:129`),
  `add_mapping` (`:189`).
- `qiling/os/path.py:16` - `QlOsPath` - `virtual_to_host_path` (`:311`),
  `is_safe_host_path` (`:326`), `host_to_virtual_path` (`:268`).
- `qiling/os/filestruct.py:18` - `ql_file` - fd object interface
  (`read/write/fileno/lseek/close/fstat/fcntl`); `PersistentQlFile` (`:97`)
  for stdio.
- `qiling/os/thread.py:11` - `QlThread(Greenlet)`.

## Interactions

- Instantiated by [core.md](core.md): memory at `qiling/core.py:188`, the
  concrete OS at `:189` via `select_os`.
- Uses [arch.md](arch.md) calling conventions inside `QlFunctionCall`.
- Subclassed by [os-posix.md](os-posix.md) (`QlOsPosix`),
  [os-windows.md](os-windows.md) (`QlOsWindows`, `QlOsUefi`, `QlOsDos`),
  and [os-baremetal.md](os-baremetal.md) (`QlOsMcu`, `QlOsBlob`).
- [loader.md](loader.md) maps segments through `QlMemoryManager`;
  [hw.md](hw.md) MMIO goes through `map_mmio`.
- The heap is wrapped by `QlSanitizedMemoryHeap` in
  [extensions.md](extensions.md); fake stdio streams from
  `qiling/extensions/pipe.py` are assigned to `ql.os.stdin/stdout`.
- [kernel-proxy.md](kernel-proxy.md) stores `ql_proxy_fd` objects in the
  POSIX fd table, relying on the `ql_file` duck-typed interface.

## How to Test

```sh
cd tests && python3 test_pathutils.py && python3 test_struct.py   # pass = both print "OK", exit 0
```

- `tests/test_pathutils.py:30` proves rootfs path virtualization (POSIX
  cases run on Linux; NT cases skip, `:74`); `tests/test_struct.py:202`
  proves the struct helpers (four wchar cases are skipped as broken,
  `:170`, `:185`).
- Memory manager and heap have no unit tests; they are proven by every OS
  suite and `tests/test_uefi.py::test_x8664_uefi_santizier`.

## Review and Refactor Guide

- **Path handling changes** must keep `__is_safe_host_path` as the last
  check before any host `open`; add cases to `tests/test_pathutils.py`.
- **Memory manager changes**: `map_info` labels are parsed by
  `get_lib_base` and by the coverage/report extensions; keep the
  `[boxed] name` label format.
- **New fcall parameter types** go in `qiling/os/const.py` with a resolver
  in `QlOs.resolvers`; OS-specific aliases live in the OS module
  (`qiling/os/windows/api.py`).
- **Do not** add OS-specific branches to `QlOs`; override in the
  personality instead (see `QlOsPosix.set_api`, `qiling/os/posix/posix.py:149`).
- Improvement candidates (proposals): bound `read_cstring`
  (`qiling/os/utils.py:88`, `TODO.md:659-661`) so a missing terminator on
  MMIO cannot spin; implement `QlOs.save/restore` for Windows/UEFI
  (`TODO.md:663-665`). Success check: a regression case in
  `tests/test_elf.py` or `tests/test_uefi.py`.

## Open Gaps / Roadmap

- Multithread emulation (gevent) is opt-in via `multithread=True` and
  cooperative only; `TODO.md:429-525` sketches a real-thread design as a
  proposal.
- `QlOs.run()` is a loose contract: each personality implements its own
  loop.
- No unit tests for `QlMemoryManager`/`QlMemoryHeap`.
