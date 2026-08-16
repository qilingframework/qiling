# OS base — shared OS-layer services

## Goal

Own the OS-agnostic services every OS personality builds on: the abstract
`QlOs` class, the emulated memory manager and heap, function-call argument
marshalling (via calling conventions), filesystem virtualization (rootfs
confinement + host mapping), file descriptor objects, green threads, and
API-call statistics. Mature released infrastructure; maturity-based status.

## Status

`done` — path virtualization and struct helpers have dedicated unit tests;
everything else is exercised by every OS suite.

## Code Structure

| File | Role |
| ---- | ---- |
| `qiling/os/os.py` | Abstract `QlOs`: utils/stats/path/fs-mapper composition, `set_api`, user-defined API dict, abstract `run()` |
| `qiling/os/memory.py` | `QlMemoryManager` (map/unmap/search, `ql.mem`) and `QlMemoryHeap` |
| `qiling/os/fcall.py` | `QlFunctionCall`: read args / write retval using `qiling/cc/` conventions |
| `qiling/os/mapper.py` | `QlFsMapper`/`QlFsMappedObject`: redirect emulated paths to host files/objects |
| `qiling/os/path.py` | `QlOsPath`: rootfs confinement and virtual→host path conversion |
| `qiling/os/filestruct.py`, `disk.py` | File-descriptor and raw-disk objects |
| `qiling/os/thread.py` | `QlThread(Greenlet)` base for multithread emulation |
| `qiling/os/stats.py` | `QlOsStats`: API/syscall call statistics |
| `qiling/os/struct.py`, `utils.py`, `const.py` | ctypes-based struct helpers, OS utils, shared constants |

## Key Types and Entry Points

- `qiling/os/os.py:24` - `QlOs` - composes utils/stats/path/fs-mapper; `user_defined_api` keyed by `QL_INTERCEPT`; abstract `run()` (`:239`).
- `qiling/os/os.py:224` - `QlOs.set_api(target, handler, intercept)` - user override of an emulated API (address- or name-based).
- `qiling/os/memory.py:23` - `QlMemoryManager` - `ql.mem`; instantiated by core *before* the OS (`qiling/core.py:188`).
- `qiling/os/memory.py:658` - `QlMemoryHeap` - heap used by Windows/UEFI APIs and the sanitizers extension.
- `qiling/os/fcall.py:21` - `QlFunctionCall` - argument/return marshalling on top of `qiling/cc/`.
- `qiling/os/mapper.py:64` - `QlFsMapper` - behind `ql.add_fs_mapper` (`qiling/core.py:701`).
- `qiling/os/path.py:14` - `QlOsPath` - rootfs-confined path resolution.
- `qiling/os/thread.py:11` - `QlThread(Greenlet)` - gevent-based thread base.

## Interactions

- Instantiated by [core.md](core.md): memory at `qiling/core.py:188`, the concrete OS at `:189` (via `select_os`).
- Uses [arch.md](arch.md) calling conventions (`qiling/cc/`) inside `QlFunctionCall`.
- Subclassed by [os-posix.md](os-posix.md) (`QlOsPosix`), [os-windows.md](os-windows.md) (`QlOsWindows`, `QlOsUefi`, `QlOsDos`), and [os-baremetal.md](os-baremetal.md) (`QlOsMcu`, `QlOsBlob`).
- [loader.md](loader.md) maps segments through `QlMemoryManager`.
- The heap is wrapped by `QlSanitizedMemoryHeap` in [extensions.md](extensions.md).

## How to Test

```sh
cd tests && python3 test_pathutils.py && python3 test_struct.py   # pass = both print "OK", exit 0
```

- `test_pathutils.py` proves rootfs path virtualization (incl. case-insensitive Windows semantics); `test_struct.py` proves the struct helpers.

## Open Gaps / Roadmap

- Multithread emulation (gevent) is opt-in via `multithread=True` and less battle-tested than single-threaded mode (see `tests/test_elf_multithread.py`).
- `QlOs.run()` contract is loose: each personality implements its own loop; no shared scheduler outside POSIX threads and MCU multitask.
