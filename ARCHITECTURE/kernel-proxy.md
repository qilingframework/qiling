---
eatmycode_version: "1.1.0"
---

# Kernel proxy — hybrid syscall forwarding to a real Linux kernel

## Goal

Let a user forward individually chosen Linux syscalls from the emulated
guest to a real Linux kernel through a helper process, without touching
the POSIX dispatcher. Owns the `KernelProxy` API, the IPC protocol, the
proxy subprocess, the `ql_proxy_fd` fd object, and argument descriptors.
It must not change `load_syscall`, existing handlers, or the fd table
code (`TODO.md:65-79`). Serves the "Hybrid Kernel Architecture" roadmap in
`TODO.md`, Phase 0.

## Status

`in progress (Phase 0)` — Phase 0 (proof of concept) is implemented:
lifecycle, raw and buffer-carrying forwarding, FD translation, user-hook
interplay. `tests/test_kernel_proxy.py` has 21 cases; 20 pass and
`test_ptr_out_writes_back_to_guest_memory` errors with `EBADF` at
`tests/test_kernel_proxy.py:451` because the test closes proxy-side fds in
the Qiling process (see Open Gaps). Phases 1–5 (`TODO.md:271-622`) are not
started. Linux hosts only (`qiling/os/posix/kernel_proxy/__init__.py:62`).

## Code Structure

| File | Role |
| ---- | ---- |
| `qiling/os/posix/kernel_proxy/__init__.py` | `KernelProxy`: starts the subprocess, resolves guest/host syscall numbers, registers CALL hooks, marshals buffers |
| `qiling/os/posix/kernel_proxy/ipc.py` | Wire format, `ProxyClient` (Qiling side) and `ProxyServer` (proxy side) |
| `qiling/os/posix/kernel_proxy/proxy.py` | Subprocess entry point: `libc.syscall()` execution and proxy-side fd ops |
| `qiling/os/posix/kernel_proxy/proxy_fd.py` | `ql_proxy_fd`: fd-table object whose real fd lives in the proxy |
| `qiling/os/posix/kernel_proxy/argtypes.py` | `INT`, `FD`, `PtrIn`, `PtrOut`, `PtrInOut` descriptors |

## Language and Conventions

Python; root rules apply. This package uses `from __future__ import
annotations`, `TYPE_CHECKING` guards, and module docstrings with usage
examples (`qiling/os/posix/kernel_proxy/__init__.py:6-28`). Errors are `QlErrorArch`,
`QlErrorSyscallNotFound`, `QlErrorSyscallError`, and
`QlProxyConnectionError` (`qiling/exception.py:77`). The proxy process logs
through the standard `logging` module, not `ql.log`, because it has no
`Qiling` instance (`qiling/os/posix/kernel_proxy/proxy.py:28`).

## Design and Invariants

- **Integration is only `set_syscall`**: `forward_syscall` registers a
  CALL hook named `ql_syscall_<name>`
  (`qiling/os/posix/kernel_proxy/__init__.py:136-166`, `:211`), so
  user ENTER/EXIT hooks still fire around it and a later user CALL hook
  overrides it (`tests/test_kernel_proxy.py:186-257`).
- **Two syscall tables**: guest numbers come from the guest arch table and
  host numbers from the host `platform.machine()` table, both read from
  `qiling/os/linux/map_syscall.py`
  (`qiling/os/posix/kernel_proxy/__init__.py:97-126`, `:278-302`).
  Unsupported host architectures raise `QlErrorArch`.
- **Wire format** is length-prefixed binary over a Unix socketpair with
  three message types: `SYSCALL`, `SYSCALL_EX` (with in/out buffers), and
  `FD_OP` (`qiling/os/posix/kernel_proxy/ipc.py:25-72`). Buffers are copied
  from/to guest memory by the forwarder
  (`qiling/os/posix/kernel_proxy/__init__.py:237-265`); the proxy never
  touches guest memory.
- **FD translation**: `FD` args must refer to a `ql_proxy_fd`, otherwise
  the forwarder raises (`qiling/os/posix/kernel_proxy/__init__.py:213-235`,
  `tests/test_kernel_proxy.py:397`); `returns_fd=True` wraps the result and
  stores it in the next free `ql.os.fd` slot
  (`qiling/os/posix/kernel_proxy/__init__.py:304-311`).
- **Lifecycle**: the subprocess starts in `__init__`
  (`qiling/os/posix/kernel_proxy/__init__.py:73-95`) with the repository
  root prepended to `PYTHONPATH`; `stop()` terminates then kills
  (`:313-330`); `__del__` calls `stop()`. The forwarder closure holds a
  weakref so registered hooks do not keep the proxy alive
  (`tests/test_kernel_proxy.py:498`).
- **Trust boundary**: forwarded syscalls execute on the host with the
  caller's privileges and no namespace isolation (`TODO.md:398-405` is a
  proposal). Only explicitly forwarded syscalls leave the sandbox; nothing
  is forwarded by default.

## Key Types and Entry Points

- `qiling/os/posix/kernel_proxy/__init__.py:54` - `KernelProxy(ql)` -
  `forward_syscall(name, returns_fd=False, arg_types=None)` (`:136`),
  `stop()` (`:313`).
- `qiling/os/posix/kernel_proxy/__init__.py:168` - `_make_forwarder` - the
  CALL-hook closure; `_translate_args` (`:213`), `_collect_buffers`
  (`:237`), `_writeback_buffers` (`:259`), `_alloc_fd` (`:304`).
- `qiling/os/posix/kernel_proxy/ipc.py:85` - `ProxyClient` - `syscall`
  (`:91`), `syscall_ex` (`:108`), `fd_read/fd_write/fd_close/fd_dup/
  fd_fcntl/fd_ioctl` (`:173-196`).
- `qiling/os/posix/kernel_proxy/ipc.py:202` - `ProxyServer` -
  `recv_request` (`:208`) and the three `send_*_response` methods.
- `qiling/os/posix/kernel_proxy/proxy.py:120` - `main()` - request loop;
  `raw_syscall` (`:41`), `raw_syscall_ex` (`:54`), `handle_fd_op` (`:84`).
- `qiling/os/posix/kernel_proxy/proxy_fd.py:22` - `ql_proxy_fd` -
  `read/write/close/fileno/dup/fcntl/ioctl` matching the `ql_file` surface.
- `qiling/os/posix/kernel_proxy/argtypes.py:46,55,64` - `PtrIn`, `PtrOut`,
  `PtrInOut` (size as int or callable over the raw args).

## Interactions

- Consumes [os-posix.md](os-posix.md): `QlOsPosix.set_syscall`,
  `ql.os.fd`, and the `map_syscall.py` tables; existing handlers such as
  `ql_syscall_read/write/close` operate on `ql_proxy_fd` unchanged.
- Uses [core.md](core.md) `ql.mem.read/write` for buffer marshalling and
  `ql.log` for diagnostics.
- Has no dependency from any other module; nothing in `qiling/` imports it
  (verified by grep), so it is strictly optional.
- Examples in `TODO.md:86-109` show the intended user flow (epoll
  forwarding); `examples/` has no script yet.

## How to Test

```sh
cd tests && python3 test_kernel_proxy.py   # Linux host; currently "Ran 21 tests … FAILED (errors=1)"
```

- Expected after the Open Gaps fix: `Ran 21 tests … OK`. Every case builds
  a `Qiling` on `examples/rootfs/x8664_linux/bin/x8664_hello` and invokes
  the registered hook directly.
- Non-Linux hosts skip the whole class (`tests/test_kernel_proxy.py:17`).
- No end-to-end test runs a guest binary that actually issues a forwarded
  syscall (`TODO.md:251-259` lists the intended validation).

## Review and Refactor Guide

- **Adding a forwarded-syscall feature** must not modify
  `qiling/os/posix/posix.py`; extend `argtypes.py` and the forwarder
  instead, and add a message type to `ipc.py` if the wire format grows.
- **Wire-format changes** must update both `ProxyClient` and
  `ProxyServer`, and the format comment at
  `qiling/os/posix/kernel_proxy/ipc.py:40-52`.
- **Security review** focuses on `_collect_buffers`/`_writeback_buffers`
  sizes (guest-controlled via `PtrOut(size=callable)`) and on which
  syscalls a harness chooses to forward; there is no allow-list.
- Improvement candidate (accepted by the test's own intent): the
  `PtrOut` test should release proxy-side fds through `FD_OP CLOSE`, not
  host `os.close`. Success check: `test_ptr_out_writes_back_to_guest_memory`
  passes.

## Open Gaps / Roadmap

- `tests/test_kernel_proxy.py:449-451` closes proxy-side fds in the wrong
  process; the test errors on every Linux host.
- Phase 1 networking (`ql_proxy_socket`, socket CALL hooks,
  `TODO.md:271-361`), Phase 2 epoll/poll/namespaces (`:363-427`), Phase 3
  real threading (`:429-525`), Phase 4 signals (`:527-567`), Phase 5 API
  and fallback (`:569-622`) are unimplemented proposals.
- No `examples/` script and no documentation outside `TODO.md` and the
  module docstring.
