---
eatmycode_version: "2.1.0"
---

# Linux Kernel Proxy

Owner: [Project architecture](../../ARCHITECTURE.md)

Read when: changing qiling/os/posix/kernel_proxy/, forwarded syscalls, proxy descriptors or the hybrid-kernel design in TODO.md.

## Responsibility and Status

Owns opt-in forwarding of selected Linux syscalls through a helper process,
argument/buffer transport and proxy-owned descriptors. **In progress:**
Phase 0 code exists; 20 of 21 tests pass and the pipe2 write-back case
errors on descriptor cleanup (Known Gaps). Actual guest dispatch and
cross-ABI buffer semantics have unresolved gaps. Later phases in
[TODO.md](../../TODO.md) remain designs, not implemented capability.

## Code Map

| Path / symbol | Role |
| --- | --- |
| [__init__.py](../../qiling/os/posix/kernel_proxy/__init__.py): `KernelProxy` | Helper lifecycle, hook registration, syscall-number/argument translation |
| [argtypes.py](../../qiling/os/posix/kernel_proxy/argtypes.py): `PtrIn`, `PtrOut`, `PtrInOut` | Integer/callable buffer-size descriptors; INT/FD tags |
| [ipc.py](../../qiling/os/posix/kernel_proxy/ipc.py): `ProxyClient` | Length-prefixed binary request/reply protocol |
| [proxy.py](../../qiling/os/posix/kernel_proxy/proxy.py), [proxy_fd.py](../../qiling/os/posix/kernel_proxy/proxy_fd.py) | libc syscall execution and guest wrapper around helper-owned fds |
| [test_kernel_proxy.py](../../tests/test_kernel_proxy.py), [TODO.md](../../TODO.md) | IPC, fd, marshalling tests and established phased design |

## Local Conventions

[Root conventions](../../ARCHITECTURE.md#code-conventions) apply. Descriptor
classes use dataclasses/type hints; `ql_proxy_fd` follows existing fd-object
naming. **Required project-specific constraint:** integrate through
`set_syscall` CALL hooks and existing fd interfaces only; do not modify
`load_syscall`, existing handlers or the emulation loop for this feature
(`TODO.md`, “What Changes vs What Doesn't”).

## Contracts and Invariants

- Constructor requires a Linux host and starts a Python helper connected by
  Unix socketpair. `forward_syscall` explicitly registers selected names;
  no automatic forwarding or dispatcher fallback is implemented.
- Guest and host syscall numbers are resolved separately. Host support is
  the explicit architecture map in `_load_host_syscall_table`; descriptor
  bytes are not automatically converted between guest/host structure ABIs.
- INT passes integers; FD requires a proxy-owned guest fd. Pointer tags copy
  bytes to/from helper buffers; `returns_fd=True` allocates a guest wrapper.
  Raw host pointers and ordinary guest fds are not interchangeable with
  translated buffers/proxy fds. Size callbacks currently see translated args.
- Wire messages include SYSCALL, SYSCALL_EX and FD_OP. Short/closed reads
  raise `QlProxyConnectionError`; sizes are encoded in protocol fields but
  no comprehensive resource quota is established (`ipc.py`, `proxy.py`).
- Helper calls are real host operations with helper-process credentials,
  not a separate security sandbox. Call `stop()` in caller `finally` cleanup;
  `KernelProxy` has no context-manager protocol.
  Do not promise automatic cleanup merely because `ql.run()` returned.
  Proxy descriptors cannot be closed by parent-process fd numbers.

## Dependencies and Boundaries

Read [POSIX](posix.md) for CALL signature introspection, errno and fd
consumers; [OS base](os-base.md) for memory/file abstractions. The helper
owns actual descriptors; the emulator owns wrappers and guest memory.
Buffer sizes, raw syscalls and IPC payloads are host trust/resource boundaries.
No additional runtime package is required beyond the existing manifest.

## Change Guide

| Change trigger | Inspect / extend | Required docs / checks |
| --- | --- | --- |
| Forwarded call/argument type | Hook signature, guest/host maps, buffer layout | Read POSIX; direct marshalling plus actual guest trap regression |
| IPC/fd operation | Both protocol endpoints, proxy wrapper/lifetime | Round-trip/error tests and POSIX fd consumer |
| Phase advancement | Current code versus TODO design | Keep this status current; prove named end-to-end behavior |

## Verification

From `tests/`: `python -m unittest test_kernel_proxy` ran 21 tests on
Linux x86_64 (WSL2)/Python 3.13 with current hello fixtures during the
latest refresh: 20 passed and `test_ptr_out_writes_back_to_guest_memory`
errored with `EBADF` after its assertions passed. Helpers invoke real
Linux syscalls. These tests exercise IPC and direct hook invocation; they
do not establish complete guest-trap integration or cross-architecture
struct conversion. Run an actual emulated syscall case for dispatch changes.

## Known Gaps

`KernelProxy._make_forwarder` returns `(ql, *args)`, while POSIX dispatch
counts only ordinary positional parameters; tests calling the hook directly
can miss missing guest arguments. `test_ptr_out_writes_back_to_guest_memory`
closes helper-owned fd numbers with parent `os.close`; depending on parent
fd allocation this fails with `EBADF` or closes an unrelated parent
descriptor. Its marshalling assertions pass; fix cleanup to go through the
proxy fd wrapper or the helper before treating the suite as green.
Buffer quotas, ABI translation and concurrent IPC access need evidence;
none should be implied by Phase 0 passing tests. Preserve scope and record
required fixes before claiming later TODO milestones.
