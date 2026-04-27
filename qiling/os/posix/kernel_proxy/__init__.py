#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

"""
Hybrid kernel proxy — forward specific syscalls to a real Linux kernel.

Usage:
    from qiling import Qiling
    from qiling.os.posix.kernel_proxy import KernelProxy, FD, PtrIn, PtrOut

    ql = Qiling(argv=["/bin/myserver"], rootfs="rootfs/x8664_linux")
    proxy = KernelProxy(ql)

    # integer-arg syscall returning a new FD
    proxy.forward_syscall("epoll_create1", returns_fd=True)

    # epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
    proxy.forward_syscall("epoll_ctl",
                          arg_types=(FD, "int", FD, PtrIn(size=12)))

    # epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
    proxy.forward_syscall("epoll_wait",
                          arg_types=(FD, PtrOut(size=lambda a: a[2] * 12), "int", "int"))

    ql.run()
"""

from __future__ import annotations

import os
import sys
import socket
import subprocess
import weakref
from typing import Dict, Optional, Sequence, Tuple, TYPE_CHECKING

from qiling.const import QL_INTERCEPT
from qiling.exception import QlErrorArch, QlErrorSyscallError, QlErrorSyscallNotFound
from qiling.os.posix.kernel_proxy.argtypes import (
    INT, FD, PtrIn, PtrOut, PtrInOut, is_pointer,
)
from qiling.os.posix.kernel_proxy.ipc import ProxyClient
from qiling.os.posix.kernel_proxy.proxy_fd import ql_proxy_fd

if TYPE_CHECKING:
    from qiling import Qiling


__all__ = ['KernelProxy', 'INT', 'FD', 'PtrIn', 'PtrOut', 'PtrInOut']


class KernelProxy:
    """Forward specific syscalls to a real Linux kernel via a helper process.

    The proxy process executes real syscalls and returns results. Integration
    is through set_syscall() CALL hooks — no changes to Qiling's dispatch code.
    """

    def __init__(self, ql: Qiling):
        if sys.platform != 'linux':
            raise QlErrorArch("KernelProxy requires a Linux host")

        self.ql = ql
        self._process: Optional[subprocess.Popen] = None
        self._client: Optional[ProxyClient] = None
        self._forwarded: Dict[str, int] = {}  # name -> syscall_nr
        self._reverse_table: Optional[Dict[str, int]] = None  # name -> nr (built on first use)

        self._start_proxy()

    def _start_proxy(self):
        """Start the proxy subprocess, connected via Unix socketpair."""
        parent_sock, child_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

        child_fd = child_sock.fileno()

        # ensure the subprocess can find qiling even when run from a subdirectory
        env = os.environ.copy()
        qiling_root = os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
        python_path = env.get('PYTHONPATH', '')
        env['PYTHONPATH'] = f"{qiling_root}:{python_path}" if python_path else qiling_root

        self._process = subprocess.Popen(
            [sys.executable, '-m', 'qiling.os.posix.kernel_proxy.proxy', str(child_fd)],
            pass_fds=(child_fd,),
            close_fds=True,
            env=env,
        )
        child_sock.close()

        self._client = ProxyClient(parent_sock)
        self.ql.log.info(f"kernel proxy started (pid={self._process.pid})")

    def _build_reverse_table(self) -> Dict[str, int]:
        """Build name -> syscall_nr mapping from the guest architecture's syscall table."""
        if self._reverse_table is not None:
            return self._reverse_table

        from qiling.const import QL_ARCH

        # get the raw syscall table dict for this architecture
        arch_tables = {
            QL_ARCH.ARM64   : 'arm64_syscall_table',
            QL_ARCH.ARM     : 'arm_syscall_table',
            QL_ARCH.X8664   : 'x8664_syscall_table',
            QL_ARCH.X86     : 'x86_syscall_table',
            QL_ARCH.MIPS    : 'mips_syscall_table',
            QL_ARCH.RISCV   : 'riscv32_syscall_table',
            QL_ARCH.RISCV64 : 'riscv64_syscall_table',
            QL_ARCH.PPC     : 'ppc_syscall_table',
        }

        table_name = arch_tables.get(self.ql.arch.type)
        if table_name is None:
            raise QlErrorArch(f"KernelProxy: unsupported architecture {self.ql.arch.type}")

        import qiling.os.linux.map_syscall as mod
        table = getattr(mod, table_name)

        # reverse: name -> nr
        self._reverse_table = {name: nr for nr, name in table.items()}
        return self._reverse_table

    def _resolve_syscall_nr(self, name: str) -> int:
        """Resolve a syscall name to its number for the guest architecture."""
        table = self._build_reverse_table()
        if name not in table:
            raise QlErrorSyscallNotFound(
                f"KernelProxy: syscall '{name}' not found in {self.ql.arch.type.name} syscall table"
            )
        return table[name]

    def forward_syscall(self, name: str, returns_fd: bool = False,
                        arg_types: Optional[Sequence] = None):
        """Register a CALL hook that forwards this syscall to the kernel proxy.

        Args:
            name: syscall name (e.g. "epoll_create1", "eventfd2").
            returns_fd: if True, wrap the return value in ql_proxy_fd and store
                        it in the Qiling FD table. Use this for syscalls that
                        return file descriptors (epoll_create1, eventfd2, etc.).
            arg_types: optional per-arg descriptors. Each entry is one of:
                       INT (or "int") — pass through unchanged (default).
                       FD (or "fd")   — guest FD; translated to the proxy FD.
                       PtrIn(size)    — pointer; bytes copied from guest to proxy.
                       PtrOut(size)   — pointer; bytes copied back from proxy to guest.
                       PtrInOut(size) — pointer; both directions.
                       If omitted, all arguments are treated as INT.
        """
        nr = self._resolve_syscall_nr(name)
        self._forwarded[name] = nr

        forwarder = self._make_forwarder(name, nr, returns_fd, arg_types)
        self.ql.os.set_syscall(name, forwarder, QL_INTERCEPT.CALL)

        kind = []
        if returns_fd:
            kind.append('returns FD')
        if arg_types:
            kind.append(f'arg_types={tuple(type(a).__name__ if not isinstance(a, str) else a for a in arg_types)}')

        suffix = f" [{', '.join(kind)}]" if kind else ''
        self.ql.log.info(f"forwarding syscall '{name}' (nr={nr}) to kernel proxy{suffix}")

    def _make_forwarder(self, name: str, guest_nr: int, returns_fd: bool,
                        arg_types: Optional[Sequence]):
        """Create a CALL hook closure for one syscall.

        Captures only the data the closure needs (host syscall nr, client, weakref
        to self) so the registered hook does not keep the KernelProxy alive.
        """
        # resolve once at registration time so the hot path stays simple
        host_nr = self._get_host_syscall_nr(name)
        client = self._client
        weak_self = weakref.ref(self)

        # normalize arg_types to a tuple, treating the string aliases as-is
        spec = tuple(arg_types) if arg_types else ()
        has_pointers = any(is_pointer(s) for s in spec)

        def _forwarder(ql, *args):
            self_ref = weak_self()
            if self_ref is None:
                ql.log.error(f"kernel_proxy: {name}() called after proxy was destroyed")
                return -1

            translated = self_ref._translate_args(name, args, spec)

            if has_pointers:
                in_bufs, out_specs, out_arg_indices = self_ref._collect_buffers(
                    ql, translated, spec
                )
                retval, out_data = client.syscall_ex(host_nr, translated, in_bufs, out_specs)
                self_ref._writeback_buffers(ql, args, out_arg_indices, out_data)
            else:
                retval = client.syscall(host_nr, translated)

            if returns_fd and retval >= 0:
                proxy_fd_obj = ql_proxy_fd(client, retval)
                guest_fd = self_ref._alloc_fd(ql, proxy_fd_obj)
                ql.log.debug(f"kernel_proxy: {name}() -> proxy_fd={retval}, guest_fd={guest_fd}")
                return guest_fd

            ql.log.debug(f"kernel_proxy: {name}({', '.join(f'{a:#x}' for a in args)}) = {retval}")
            return retval

        _forwarder.__name__ = f'ql_syscall_{name}'
        return _forwarder

    def _translate_args(self, name: str, args: Tuple[int, ...],
                        spec: Tuple) -> Tuple[int, ...]:
        """Translate guest FD args to proxy FD numbers; pad to 6 args.

        Pointer args are left untouched here — _collect_buffers replaces them
        with the proxy-side buffer addresses just before invocation.
        """
        out = list(args) + [0] * (6 - len(args))

        for idx, kind in enumerate(spec):
            if kind == FD:
                guest_fd = args[idx]
                fd_obj = self.ql.os.fd[guest_fd] if 0 <= guest_fd < len(self.ql.os.fd) else None

                if not isinstance(fd_obj, ql_proxy_fd):
                    raise QlErrorSyscallError(
                        f"kernel_proxy: {name}() arg{idx} guest_fd={guest_fd} "
                        f"does not refer to a proxy-owned FD"
                    )

                out[idx] = fd_obj._proxy_fd

        return tuple(out[:6])

    def _collect_buffers(self, ql, args: Tuple[int, ...], spec: Tuple):
        """Read PtrIn/PtrInOut buffers from guest memory; collect PtrOut sizes."""
        in_bufs = []
        out_specs = []
        out_arg_indices = []

        for idx, kind in enumerate(spec):
            if isinstance(kind, (PtrIn, PtrInOut)):
                size = kind.resolve(args)
                if size > 0:
                    data = bytes(ql.mem.read(args[idx], size))
                    in_bufs.append((idx, data))

            if isinstance(kind, (PtrOut, PtrInOut)):
                size = kind.resolve(args)
                if size > 0:
                    out_specs.append((idx, size))
                    out_arg_indices.append(idx)

        return in_bufs, out_specs, out_arg_indices

    @staticmethod
    def _writeback_buffers(ql, args: Tuple[int, ...],
                           out_arg_indices: Sequence[int],
                           out_data: Sequence[bytes]):
        """Write PtrOut/PtrInOut response buffers back into guest memory."""
        for idx, data in zip(out_arg_indices, out_data):
            if data:
                ql.mem.write(args[idx], data)

    def _get_host_syscall_nr(self, name: str) -> int:
        """Get the syscall number on the HOST architecture."""
        # we are running on Linux — read from the host's syscall table
        if not hasattr(self, '_host_table'):
            self._host_table = self._load_host_syscall_table()

        if name not in self._host_table:
            raise QlErrorSyscallNotFound(f"KernelProxy: syscall '{name}' not available on host")

        return self._host_table[name]

    def _load_host_syscall_table(self) -> Dict[str, int]:
        """Load the host's syscall name->nr mapping.

        Uses the same Qiling tables, indexed by the host architecture.
        """
        import platform
        import qiling.os.linux.map_syscall as mod

        machine = platform.machine()
        host_arch_map = {
            'x86_64':  'x8664_syscall_table',
            'aarch64': 'arm64_syscall_table',
            'armv7l':  'arm_syscall_table',
            'mips':    'mips_syscall_table',
            'riscv64': 'riscv64_syscall_table',
            'ppc':     'ppc_syscall_table',
        }

        table_name = host_arch_map.get(machine)
        if table_name is None:
            raise QlErrorArch(f"KernelProxy: unsupported host architecture '{machine}'")

        table = getattr(mod, table_name)
        return {name: nr for nr, name in table.items()}

    @staticmethod
    def _alloc_fd(ql, fd_obj) -> int:
        """Find next free slot in Qiling's FD table and store fd_obj."""
        for i in range(len(ql.os.fd)):
            if ql.os.fd[i] is None:
                ql.os.fd[i] = fd_obj
                return i

        raise QlErrorSyscallError("kernel_proxy: FD table full")

    def stop(self):
        """Stop the proxy process."""
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

        if self._process:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait()
            self.ql.log.info(f"kernel proxy stopped (pid={self._process.pid})")
            self._process = None

    def __del__(self):
        if hasattr(self, '_client'):
            self.stop()
