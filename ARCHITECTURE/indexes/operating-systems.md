---
eatmycode_version: "2.0.0"
---

# Operating System Routes

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: changing guest memory/services, syscall dispatch, OS APIs or interrupts.

## Routes

| Source paths / task trigger | Responsibility | Read next |
| --- | --- | --- |
| `qiling/os/*.py`, `tests/test_pathutils.py`, `test_struct.py`; memory/heap, paths, file wrappers, call marshalling, structs | Shared OS services | [OS base](../modules/os-base.md) |
| `qiling/os/posix/` except `kernel_proxy/`, `linux/`, `freebsd/`, `macos/`, `qnx/`; `tests/test_posix.py`, ELF syscall/thread/kernel, Android/QNX/Mach-O/RISC-V/network cases; `examples/src/{linux,freebsd,macos,qnx}/` | Syscall/process personalities | [POSIX](../modules/posix.md) |
| `qiling/os/windows/`, API cases in `tests/test_pe*.py`, `test_windows*.py`, `examples/src/windows/`; Win32/NT handlers and objects | Windows APIs | [Windows](../modules/windows.md) |
| `qiling/os/uefi/`, `tests/test_uefi.py`, `qiling/profiles/uefi.ql`; services, protocols, DXE/SMM state | UEFI services | [UEFI](../modules/uefi.md) |
| `qiling/os/dos/`, `tests/test_dos*.py`, DOS examples; interrupts, files/disks/terminal | DOS personality | [DOS](../modules/dos.md) |

Image parsing in shared integration tests belongs to the runtime/loading
branch of the root Task Index. `qiling/profiles/` parsing belongs to core;
OS-specific values belong to the corresponding row above. `qiling/os/disk.py`
is shared OS-base ownership; follow its DOS partner only for interrupt consumers.
