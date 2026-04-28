# Qiling Framework TODO

Features request and TODO please refer to issue 333 https://github.com/qilingframework/qiling/issues/333

---

## Hybrid Kernel Architecture

### The Problem

Qiling reimplements Linux kernel behavior syscall-by-syscall in Python. Simple
syscalls (file I/O, memory, stat) work well. Complex subsystems do not:

- **Networking**: No epoll. Sockets are host sockets with no isolation. No TCP
  state machine, no multicast, no raw/netlink sockets.
- **Threading**: Gevent greenlets — cooperative, single-threaded. No preemption.
  Futex is a gevent Event. pthreads don't behave correctly.
- **Signals**: `signal()`, `sigaction()`, `kill()` are stubs. No delivery, no EINTR.

Reimplementing the full kernel is not realistic. Instead, offload complex subsystems
to a real Linux kernel while keeping Qiling's instrumentation intact.

### Key Insight: Two-Layer Forwarding

There are two integration points, each serving a different purpose:

**Layer 1 — Generic fallback** (catches the long tail):

The user explicitly chooses which missing syscalls to forward. Nothing is automatic.
By default Qiling behaves exactly as it does today — if a syscall is not implemented,
it fails. The user then tells the proxy which specific syscalls to forward:

```python
ql = Qiling(argv=["/bin/myserver"], rootfs="rootfs/x8664_linux")
proxy = KernelProxy(ql)                    # start proxy process
proxy.forward_syscall("epoll_create")      # forward this one to real kernel
proxy.forward_syscall("epoll_ctl")         # and this one
proxy.forward_syscall("epoll_wait")        # and this one
ql.run()
```

Under the hood, `forward_syscall("epoll_create")` registers a CALL hook via the
existing `set_syscall()` mechanism (`posix.py:128-143`). The hook reads args from
the emulated registers, sends them to the proxy process, and returns the real result.
**Zero changes to `load_syscall()` or any existing dispatch code.**

For syscalls that return FDs (socket, epoll_create, eventfd, etc.), the proxy
wraps the returned FD in a `ql_proxy_fd` object and stores it in the FD table.
The FD table (`QlFileDes`) already stores polymorphic objects — `ql_socket`,
`ql_file`, `ql_pipe` — so `ql_proxy_fd` slots in naturally. When existing handlers
like `ql_syscall_read` or `ql_syscall_close` hit a proxy FD, they dispatch through
`ql_proxy_fd.read()` / `.close()` which forwards to the proxy.

```
Syscall interrupt
  → load_syscall() [UNCHANGED]
    → has CALL hook? (user hook or proxy-registered hook)
      → yes: use it
    → has Python handler? (existing code)
      → yes: use it [unchanged — file I/O, memory, stat, etc.]
    → neither?
      → log warning [existing behavior, unchanged — no auto-forwarding]
```

### What Changes vs What Doesn't

| Component | Changes? | Notes |
|-----------|----------|-------|
| `load_syscall()` dispatch | **NO** | Entirely unchanged |
| Existing syscall handlers | NO | Python handlers stay as-is |
| `QlFileDes` FD table | NO | Already polymorphic, new FD type slots in |
| `set_syscall()` user hooks | NO | User CALL/ENTER/EXIT hooks still work |
| `ql.run()` / `ql.emu_start()` | NO | Unicorn execution loop untouched |
| Hook system (`core_hooks.py`) | NO | Standard Unicorn hook mechanism |
| New: kernel proxy process | YES | New module, new files only |
| New: `ql_proxy_fd` FD type | YES | New class, same interface as `ql_socket` |
| New: `KernelProxy` class | YES | User-facing API, registers CALL hooks |

---

## Phase 0: Proof of Concept

**Goal**: User can explicitly forward specific unimplemented syscalls to a real Linux
kernel. No automatic behavior. No changes to existing Qiling dispatch code.

### Usage

```python
from qiling import Qiling
from qiling.os.posix.kernel_proxy import KernelProxy

ql = Qiling(argv=["/bin/myserver"], rootfs="rootfs/x8664_linux")

# Start a kernel proxy — a helper process that executes real syscalls
proxy = KernelProxy(ql)

# Binary needs epoll but Qiling doesn't implement it.
# User identifies the 3 missing syscalls and forwards them:
proxy.forward_syscall("epoll_create")
proxy.forward_syscall("epoll_ctl")
proxy.forward_syscall("epoll_wait")

ql.run()
# epoll_create/ctl/wait are handled by real kernel.
# Everything else (read, write, open, mmap, ...) uses existing Qiling handlers.
```

If the user does NOT set up a proxy, Qiling behaves exactly as it does today.
No surprises, no magic.

### 0.1 Kernel proxy process

A standalone Python process that executes real Linux syscalls on behalf of Qiling.
Communicates via Unix socketpair.

- [ ] New directory: `qiling/os/posix/kernel_proxy/`
- [ ] `proxy.py` — proxy subprocess entry point
  - Main loop: read request from socket → `libc.syscall(nr, *args)` → write response
  - Uses `ctypes.CDLL("libc.so.6").syscall()` for raw syscall execution
  - Manages its own FD table (proxy-side FDs)
- [ ] IPC protocol (binary, over socketpair):
  ```
  Request:  { type: SYSCALL, syscall_nr: u32, args: [u64; 6] }
  Response: { return_value: i64, errno: i32 }

  Request:  { type: FD_OP, op: READ|WRITE|CLOSE, proxy_fd: i32, length: u32, data?: bytes }
  Response: { return_value: i64, errno: i32, data?: bytes }
  ```
  Two message types: raw syscall forwarding, and FD operations (for read/write/close
  on proxy-owned FDs).
- [ ] Lifecycle: started by `KernelProxy.__init__()`, killed on `ql.run()` exit

### 0.2 `KernelProxy` class — user-facing API

The main integration class. Lives in `qiling/os/posix/kernel_proxy/__init__.py`.

```python
class KernelProxy:
    def __init__(self, ql: Qiling):
        """Start the proxy subprocess."""
        self.ql = ql
        self._proxy_process = ...  # start subprocess
        self._ipc = ...            # socketpair connection
        self._forwarded = {}       # syscall_name → syscall_nr

    def forward_syscall(self, name: str, returns_fd: bool = False):
        """Register a CALL hook that forwards this syscall to the proxy.

        Args:
            name: syscall name (e.g. "epoll_create", "eventfd")
            returns_fd: if True, wrap the return value in ql_proxy_fd
                        and store in the FD table
        """
        # Look up syscall number from the architecture's syscall table
        # Register a CALL hook via ql.os.set_syscall()
        ql.os.set_syscall(name, self._make_forwarder(name, returns_fd))

    def _make_forwarder(self, name, returns_fd):
        """Create a CALL hook function for this syscall."""
        syscall_nr = self._resolve_syscall_nr(name)

        def forwarder(ql, *args):
            # Send all args as raw integers to proxy
            retval = self._ipc.forward(syscall_nr, args)

            if returns_fd and retval >= 0:
                # Wrap proxy FD and store in Qiling's FD table
                proxy_fd = ql_proxy_fd(self._ipc, retval)
                guest_fd = self._alloc_fd(ql, proxy_fd)
                return guest_fd

            return retval

        return forwarder
```

Key points:
- `forward_syscall()` uses the existing `set_syscall()` mechanism — a standard
  CALL hook. No special dispatch path, no changes to `load_syscall()`.
- User explicitly passes `returns_fd=True` for FD-returning syscalls. No heuristics.
- User ENTER/EXIT hooks still fire around the forwarded syscall (existing behavior
  of the hook chain in `load_syscall()` lines 206-224).

- [ ] Implement `KernelProxy` class
- [ ] Implement `_resolve_syscall_nr()` — look up syscall number from arch tables
- [ ] Implement `_make_forwarder()` — create CALL hook closure
- [ ] Implement `_alloc_fd()` — find empty slot in `ql.os.fd[]`, store `ql_proxy_fd`

### 0.3 `ql_proxy_fd` — proxy-side FD wrapper

When a forwarded syscall returns an FD (e.g., `epoll_create` returns 5 in the proxy),
we store a `ql_proxy_fd` in Qiling's FD table. This object forwards read/write/close
to the proxy, matching the interface of `ql_socket` (`filestruct.py:14`).

```python
class ql_proxy_fd:
    """FD whose real file/socket lives in the kernel proxy process."""

    def __init__(self, ipc, proxy_fd: int):
        self._ipc = ipc
        self._proxy_fd = proxy_fd

    def read(self, length: int) -> bytes:
        return self._ipc.fd_read(self._proxy_fd, length)

    def write(self, data: bytes) -> int:
        return self._ipc.fd_write(self._proxy_fd, data)

    def close(self) -> None:
        self._ipc.fd_close(self._proxy_fd)

    def fileno(self) -> int:
        return -1  # not a real host FD
```

Because `ql_syscall_read` / `ql_syscall_write` / `ql_syscall_close` already dispatch
through `ql.os.fd[fd].read()` / `.write()` / `.close()`, **these existing handlers
need no changes**. When the binary calls `read(fd, buf, n)` on a proxy FD, the
existing read handler calls `ql_proxy_fd.read(n)`, gets data back, and writes it
to guest memory as usual.

- [ ] Implement `ql_proxy_fd` class in `qiling/os/posix/kernel_proxy/proxy_fd.py`
- [ ] Verify `ql_syscall_read` works with `ql_proxy_fd` — no changes needed
- [ ] Verify `ql_syscall_write` works with `ql_proxy_fd` — no changes needed
- [ ] Verify `ql_syscall_close` works with `ql_proxy_fd` — no changes needed

### 0.4 Pointer-bearing syscalls (Phase 0 scope: one example)

Some forwarded syscalls take pointers to guest memory. The proxy can't read guest
memory directly. For Phase 0, implement ONE pointer-bearing forwarder as an example
to prove the pattern works. `epoll_ctl` is a good candidate:

```
epoll_ctl(epfd, op, fd, struct epoll_event *event)
```

The forwarder must:
1. Read `struct epoll_event` (8 bytes) from guest memory at the `event` pointer
2. Send the struct data along with the integer args to the proxy
3. Proxy reconstructs the struct in its own memory, calls real `epoll_ctl`

- [ ] Extend IPC protocol for buffer-carrying requests:
  ```
  Request:  { type: SYSCALL_WITH_BUFS, syscall_nr, args[6], buffers: [(arg_idx, direction, data)] }
  Response: { return_value, errno, buffers: [(arg_idx, data)] }
  ```
  `direction` is IN (guest→proxy), OUT (proxy→guest), or INOUT.
- [ ] Implement `forward_syscall_with_buffers()` API for pointer-bearing syscalls
- [ ] Implement `epoll_ctl` forwarder as the working example

### 0.5 Validation

- [ ] Test: binary that uses `epoll_create` + `epoll_ctl` + `epoll_wait` on a
      timerfd or eventfd. User forwards all 4 syscalls. Verify it works end-to-end.
- [ ] Test: same binary WITHOUT proxy — Qiling fails as it does today. No regression.
- [ ] Test: binary that calls `socket()` — existing Qiling handler runs (user did
      NOT forward `socket`). Verify no interference.
- [ ] Test: user `set_syscall("epoll_create", my_hook)` — user hook takes priority
      over proxy hook (user hook registered after proxy hook overwrites it via
      `set_syscall`). Verify user control is preserved.
- [ ] Test: proxy process crash — verify Qiling reports error cleanly, doesn't hang.

**Existing code modified**: NONE. All new files in `qiling/os/posix/kernel_proxy/`.
Integration is purely through `set_syscall()`.

**Risk**: LOW — new code in new module. Existing behavior completely unchanged unless
user explicitly creates a `KernelProxy` and calls `forward_syscall()`.

---

## Phase 1: Networking Foundation

**Goal**: Forward all socket syscalls. Make a TCP client work end-to-end.

### 1.1 `ql_proxy_socket` FD type

New class in `qiling/os/posix/filestruct.py` (or new file alongside it). Must match
`ql_socket` interface so generic I/O dispatches correctly:

```python
class ql_proxy_socket:
    """Socket FD whose real socket lives in the kernel proxy process."""

    def read(self, length: int) -> bytes:
        # Forward to proxy: recv(self.proxy_fd, length)
        
    def write(self, data: bytes) -> int:
        # Forward to proxy: send(self.proxy_fd, data)

    def close(self) -> None:
        # Forward to proxy: close(self.proxy_fd)

    def fileno(self) -> int:
        # Return a sentinel — not a real host FD
        
    # Socket-specific methods forwarded to proxy:
    def connect(self, address) -> None: ...
    def bind(self, address) -> None: ...
    def listen(self, backlog) -> None: ...
    def accept(self) -> tuple: ...
    def shutdown(self, how) -> None: ...
    def setsockopt(self, level, optname, value) -> None: ...
    def getsockopt(self, level, optname) -> ...: ...
```

Because `ql_syscall_read` / `ql_syscall_write` / `ql_syscall_close` already dispatch
through `ql.os.fd[fd].read()` / `.write()` / `.close()`, these **existing handlers
need no changes** — the proxy socket object handles forwarding internally.

- [ ] Implement `ql_proxy_socket` class
- [ ] IPC client method for each operation
- [ ] Verify generic `read(fd, ...)` and `write(fd, ...)` work on proxy sockets
      without modifying `ql_syscall_read` or `ql_syscall_write`

### 1.2 Socket syscall CALL hooks

Register CALL hooks for socket-specific syscalls. These are needed because socket
syscalls (bind, connect, listen, accept, etc.) have special argument handling
(sockaddr structs, address lengths) that goes beyond generic read/write.

- [ ] `socket()` — create proxy socket, store `ql_proxy_socket` in FD table
- [ ] `bind(fd, addr, addrlen)` — read sockaddr from guest memory, forward to proxy
- [ ] `connect(fd, addr, addrlen)` — same pattern
- [ ] `listen(fd, backlog)` — forward
- [ ] `accept(fd, addr, addrlen)` — forward, create new `ql_proxy_socket` for client FD
- [ ] `send/sendto/sendmsg` — read buffer from guest memory, forward
- [ ] `recv/recvfrom/recvmsg` — forward, write received data to guest memory
- [ ] `setsockopt/getsockopt` — forward with option translation
- [ ] `getpeername/getsockname` — forward, write sockaddr to guest memory
- [ ] `shutdown` — forward
- [ ] `socketpair` — forward, create two `ql_proxy_socket` objects
- [ ] `close` on proxy sockets — handled by `ql_proxy_socket.close()`,
      but also register hook to detect close on proxy FDs if needed

**Struct translation**: sockaddr family (AF_INET, AF_INET6, AF_UNIX) is the same
across architectures. Network byte order is architecture-independent. The main
concern is pointer width (32-bit guest on 64-bit host) — read the right number
of bytes from guest memory based on `ql.arch.pointersize`.

### 1.3 `socketcall()` multiplexer (x86 32-bit)

On x86 32-bit, all socket operations go through a single `socketcall()` syscall
(`qiling/os/posix/syscall/net.py`). The existing multiplexer dispatches to individual
handlers. Since we hook the individual handlers (bind, connect, etc.), this works
automatically. But verify:

- [ ] Test that x86 32-bit socket operations are correctly forwarded via the
      existing socketcall → individual handler → our CALL hook chain

### 1.4 Validation

- [ ] TCP client: connect to a server, send/receive data, close
- [ ] TCP server: bind, listen, accept, handle client, close
- [ ] UDP: sendto/recvfrom
- [ ] Unix domain sockets (path-based)
- [ ] Existing non-network tests still pass (regression check)

**Risk**: LOW-MEDIUM — new code + new FD type, but existing handlers and dispatch
untouched. Main risk is FD lifecycle bugs (leak, double-close).

---

## Phase 2: Complete Networking

**Goal**: epoll, network namespaces, advanced operations. Real-world network
binaries work.

### 2.1 epoll forwarding

epoll is currently **not implemented at all** — mapped in the syscall table but
no handler. This is new functionality, not a change to existing behavior.

- [ ] `epoll_create` / `epoll_create1` — forward, return proxy epoll FD
      (new FD type or reuse `ql_proxy_socket` with a flag)
- [ ] `epoll_ctl(epfd, op, fd, event)` — forward; `fd` must be translated to
      proxy FD space. Read `epoll_event` struct from guest memory.
- [ ] `epoll_wait(epfd, events, maxevents, timeout)` — forward. **This blocks**
      in the proxy. For single-threaded programs this is correct (binary would be
      blocked anyway). Write returned events to guest memory.
- [ ] `epoll_pwait` — same as epoll_wait + signal mask

**Blocking concern**: when the proxy is blocked on `epoll_wait`, the Unicorn
emulation is paused. This is correct for single-threaded programs. For multithreaded
programs, we need real threading (Phase 3) where each thread has its own Unicorn
and can block independently.

### 2.2 poll/select integration

Currently `poll()` and `select()` use host `select.poll()`/`select.select()` directly,
which won't work for proxy FDs (no host FD to poll).

- [ ] Hook `poll()` and `select()` — for FD sets containing proxy FDs, forward the
      entire operation to the proxy
- [ ] For mixed FD sets (some proxy, some local): forward the proxy FDs to the proxy,
      poll local FDs locally, merge results. This is complex — consider forwarding all
      FDs to the proxy as the simpler approach.

### 2.3 Network namespace isolation

- [ ] Proxy process runs in its own network namespace (`unshare(CLONE_NEWNET)`)
- [ ] Configurable modes:
  - `host`: proxy shares host network (default, simplest)
  - `isolated`: separate namespace, no connectivity
  - `bridged`: veth pair with NAT to host
- [ ] DNS: mount a resolv.conf in the proxy's mount namespace if needed

### 2.4 Advanced operations (lower priority)

- [ ] `sendmmsg` / `recvmmsg` — batch send/receive
- [ ] Raw sockets / packet sockets (`AF_PACKET`)
- [ ] Netlink sockets (`AF_NETLINK`) — for binaries that call `ip`, `route`, etc.
- [ ] `SCM_RIGHTS` (FD passing over Unix sockets) — requires FD translation
- [ ] IPv6 multicast

### 2.5 Validation

- [ ] epoll-based TCP echo server
- [ ] HTTP client (wget/curl-like binary)
- [ ] Binary that uses poll() with mixed file + socket FDs
- [ ] Network namespace: verify proxy and emulated binary are isolated from host
- [ ] Performance: measure latency overhead of IPC per syscall

**Risk**: MEDIUM — epoll is new functionality (no regression risk), but poll/select
changes for proxy FDs touch existing handlers. The mixed-FD-set case is the main
complexity.

---

## Phase 3: Real Threading

**Goal**: Real concurrency with one Unicorn engine per thread.

**This phase is high-risk and should only start after Phase 2 is stable.** It touches
the Unicorn integration, memory manager, thread lifecycle, and scheduler — all core
components. Needs a detailed design document before implementation begins.

### Prerequisites

- [ ] Phase 1-2 networking is stable and tested
- [ ] Detailed design document covering memory sharing, thread lifecycle,
      and failure modes
- [ ] Prototype benchmark: measure overhead of multiple Unicorn instances
      sharing memory via `mem_map_ptr`

### 3.1 Shared memory backing for Unicorn

Currently `QlMemoryManager.map()` calls `uc.mem_map()` which allocates internal
Unicorn memory. For shared threading, all Unicorn instances must see the same memory.

- [ ] Change memory backing to use `mmap(MAP_SHARED)` + `uc.mem_map_ptr()`
- [ ] This affects: `QlMemoryManager.map()`, `QlMemoryManager.protect()`,
      `QlMemoryManager.unmap()`
- [ ] Loader changes: ELF/PE/MachO loaders must write segments into shared-backed
      memory regions
- [ ] MMIO regions stay callback-based (not shared)
- [ ] **Critical**: This must be done as a standalone change that passes ALL existing
      tests before moving to 3.2. If existing tests break, the shared memory
      implementation is wrong.

Files: `qiling/os/memory.py`, `qiling/loader/elf.py`, `qiling/loader/pe.py`

### 3.2 One Unicorn instance per thread

Replace gevent Greenlets with real OS threads, each owning a Unicorn instance.

- [ ] New thread class: `QlLinuxRealThread` (alongside existing `QlLinuxThread`)
  - Creates a new `Uc` instance on spawn
  - Maps all shared memory regions into the new Uc via `mem_map_ptr`
  - Copies parent registers to child Uc
  - Sets child's SP, TLS, return value
  - Runs in a real `threading.Thread`
- [ ] Modify `clone()` handler: when hybrid threading is enabled, create
      `QlLinuxRealThread` instead of gevent Greenlet
- [ ] Per-thread hook context: each Unicorn instance needs its own hooks registered.
      User-defined hooks must be replicated to all instances.
- [ ] Remove the 32337-instruction cooperative scheduling loop — real OS scheduler
      handles preemption

**What breaks**: The current model assumes ONE `ql.uc` instance. Code that accesses
`ql.uc` directly will see only one thread's Unicorn. Need to audit all `ql.uc`
references and route to the current thread's instance.

Risky references:
- `ql.arch.regs` reads/writes `ql.uc` registers — must route to current thread's Uc
- `ql.mem.read/write` calls `ql.uc.mem_read/write` — with shared memory, any Uc works
- `ql.hook_*` registers on `ql.uc` — must register on all Uc instances
- `ql.save()/restore()` snapshots `ql.uc` — must snapshot correct thread

### 3.3 Synchronization primitives via real kernel

With real OS threads sharing real memory, kernel synchronization works natively.

- [ ] Forward `futex()` to kernel — `FUTEX_WAIT`/`FUTEX_WAKE` operate on the shared
      memory addresses directly
- [ ] Remove gevent Event-based futex emulation (`qiling/os/linux/futex.py`)
- [ ] Forward `set_robust_list`, `get_robust_list`
- [ ] `pthread_mutex_*`, `pthread_cond_*` — these use futex internally, so forwarding
      futex is sufficient

### 3.4 Thread safety for shared state

With real concurrent threads, shared mutable state needs synchronization.

- [ ] `QlMemoryManager`: lock `map_info` list mutations (map, unmap, protect)
  - read/write don't need locks if backed by shared mmap (atomic at OS level)
- [ ] `QlFileDes`: lock FD table mutations (open, close, dup)
- [ ] Hook lists: lock registration/deregistration (hooks are usually set up before
      `run()`, so contention should be minimal)
- [ ] Logging: thread-safe log handler with thread ID prefix

### 3.5 Validation

- [ ] pthread_create / pthread_join
- [ ] Mutex: two threads incrementing a shared counter with proper locking
- [ ] Condition variables: producer-consumer
- [ ] Futex: custom futex-based synchronization
- [ ] Thread-local storage (TLS) correctness per architecture
- [ ] Stress test: 10+ threads doing concurrent work
- [ ] ALL existing single-threaded tests still pass
- [ ] ALL existing gevent-threaded tests still pass (gevent mode preserved as fallback)

**Risk**: HIGH — changes to memory manager, Unicorn integration, and thread model.
Keep the existing gevent threading as a fallback mode. The new threading is opt-in.

---

## Phase 4: Signals

**Depends on Phase 3** (real threads required for proper signal delivery).

### 4.1 Signal handler registration

- [ ] Forward `sigaction(signum, act, oldact)` to kernel proxy
- [ ] Forward `sigprocmask` / `rt_sigprocmask`
- [ ] Forward `sigaltstack`

### 4.2 Signal delivery

When a signal is delivered to a proxy thread:

- [ ] Proxy catches the signal and sends notification to Qiling via IPC
- [ ] Qiling calls `emu_stop()` on the target thread's Unicorn
- [ ] Save thread context (registers)
- [ ] Build signal frame on emulated stack (architecture-specific)
- [ ] Set PC to the registered signal handler
- [ ] Resume Unicorn — handler executes in emulated code
- [ ] On `sigreturn` / `rt_sigreturn`: restore saved context, resume normal execution

### 4.3 Signal-syscall interaction

- [ ] `EINTR` on interrupted blocking syscalls
- [ ] `SA_RESTART` flag: automatically restart interrupted syscalls
- [ ] `kill()`, `tgkill()`, `tkill()` → forward to kernel

### 4.4 Validation

- [ ] SIGALRM handler (timer-based)
- [ ] SIGCHLD on child exit
- [ ] SIGPIPE on broken pipe
- [ ] Signal interrupting `read()` — verify EINTR
- [ ] Custom signal handler that modifies emulated state

**Risk**: MEDIUM — signal frame construction is architecture-specific and fiddly,
but the mechanism is well-understood. Main risk is getting the frame layout exactly
right for each architecture.

---

## Phase 5: Integration and Polish

### 5.1 User-facing API

```python
# Opt-in to hybrid kernel
ql = Qiling(argv=[...], rootfs="...")

# Enable kernel proxy for networking (Phase 1-2)
ql.os.kernel_proxy.enable(networking=True)

# Enable real threading (Phase 3) — requires networking=True
ql.os.kernel_proxy.enable(networking=True, threading=True)

# Enable signals (Phase 4) — requires threading=True
ql.os.kernel_proxy.enable(networking=True, threading=True, signals=True)

# Configure network namespace
ql.os.kernel_proxy.network_mode = "bridged"  # "host" | "isolated" | "bridged"

# User hooks still work — they fire before/after proxy forwarding
ql.os.set_syscall("connect", my_connect_hook, QL_INTERCEPT.ENTER)
```

### 5.2 Backward compatibility

- [ ] Default behavior: no proxy, existing Python handlers — zero regression
- [ ] All existing tests pass with proxy disabled
- [ ] All existing tests pass with proxy enabled (forwarded syscalls should
      produce equivalent results)
- [ ] `set_syscall()` user hooks fire correctly in both modes
- [ ] Existing gevent threading preserved as fallback when real threading not enabled

### 5.3 Fallback on failure

- [ ] If proxy process crashes: log error, fall back to Python handlers, warn user
- [ ] If proxy not available (non-Linux host): use Python handlers, warn user
- [ ] Graceful degradation: never crash, always fall back

### 5.4 Platform support

- [ ] Linux host: full support (namespaces, real threading)
- [ ] macOS host: proxy via Docker/Lima (networking only, no native namespaces)
- [ ] Windows host: proxy via WSL2 (networking only)
- [ ] Document host requirements

### 5.5 Performance

- [ ] Benchmark: syscall latency (Python handler vs proxy round-trip)
- [ ] Optimize IPC: shared memory ring buffer for high-frequency syscalls
- [ ] Batch small syscalls where possible
- [ ] Profile and tune for common workloads (network servers, threaded computation)

---

## Existing Issues (Independent of Hybrid Architecture)

These should be fixed regardless of the hybrid work.

### Bare except blocks swallowing errors

10+ bare `except:` blocks silently hide failures:

- `qiling/utils.py:242` — PE detection
- `qiling/debugger/qdb/qdb.py:128,352,598` — debugger operations
- `qiling/os/posix/filestruct.py:62,173,179` — fcntl/ioctl
- `qiling/os/posix/syscall/select.py:78` — select failures
- `qiling/os/windows/registry.py:127,185` — registry operations

### Asserts used for validation

Assertions disabled with `python -O`. Replace with exceptions:

- `qiling/os/memory.py` — page alignment, size, mapping checks
- `qiling/arch/x86_utils.py` — GDT/segment validation
- `qiling/cc/__init__.py` — calling convention validation

### Memory manager: string label parsing

`qiling/os/memory.py:209-218` — `get_lib_base()` uses regex on info strings.
Needs a proper mapping structure.

### ARM Thumb mode detection

`core.py:753` — fragile `_init_thumb` flag. Needs upstream Unicorn fix.

### x86 GDT privilege levels

`qiling/arch/x86_utils.py:147,178` — ring 3 forced to ring 0.

### Unbounded `read_cstring`

`qiling/os/memory.py:51-63` — no length limit. Can hang on MMIO.

### Incomplete save/restore

`QlOs.save()/restore()` empty in base class. UEFI and Windows don't implement it.

### Incomplete Windows emulation

Fiber, registry, handle management, DLL resolution gaps.
See `qiling/os/windows/` TODO comments.

### macOS and UEFI gaps

- macOS kext: 5 FIXMEs in `macos.py:79-117`
- UEFI variables: `uefi/rt.py:204-205`

### Hook system cleanup

- `type()` vs `isinstance()` in `core_hooks.py`
- Unclear return value semantics
- Non-intuitive `begin=1, end=0` for "entire memory"

### Hardcoded magic numbers

- Exit points in `os/os.py:84-87`
- Guard page `0x9000000` in `core.py:525`

### Test coverage

- ARM test skipped (`test_elf.py:411`)
- Multithread test skipped (`test_elf_multithread.py:185`)
- Broken wchar (`test_struct.py:170,185`)
- PowerPC, QNX, DOS, MCU: minimal coverage
