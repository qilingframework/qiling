#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

"""
Hybrid kernel proxy — forward specific syscalls to a real Linux kernel.

Usage:
    from qiling import Qiling
    from qiling.os.posix.kernel_proxy import KernelProxy

    ql = Qiling(argv=["/bin/myserver"], rootfs="rootfs/x8664_linux")
    proxy = KernelProxy(ql)
    proxy.forward_syscall("epoll_create", returns_fd=True)
    proxy.forward_syscall("epoll_ctl")
    proxy.forward_syscall("epoll_wait")
    ql.run()
"""

from __future__ import annotations

import os
import sys
import socket
import subprocess
from typing import Dict, Optional, TYPE_CHECKING

from qiling.const import QL_INTERCEPT, QL_OS
from qiling.exception import QlErrorArch, QlErrorSyscallError, QlErrorSyscallNotFound
from qiling.os.posix.kernel_proxy.ipc import ProxyClient
from qiling.os.posix.kernel_proxy.proxy_fd import ql_proxy_fd

if TYPE_CHECKING:
    from qiling import Qiling


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

    def forward_syscall(self, name: str, returns_fd: bool = False):
        """Register a CALL hook that forwards this syscall to the kernel proxy.

        Args:
            name: syscall name (e.g. "epoll_create", "eventfd2")
            returns_fd: if True, wrap the return value in ql_proxy_fd and store
                        in the Qiling FD table. Use this for syscalls that return
                        file descriptors (epoll_create, eventfd, timerfd_create, etc.)
        """
        nr = self._resolve_syscall_nr(name)
        self._forwarded[name] = nr

        forwarder = self._make_forwarder(name, nr, returns_fd)
        self.ql.os.set_syscall(name, forwarder, QL_INTERCEPT.CALL)

        self.ql.log.info(f"forwarding syscall '{name}' (nr={nr}) to kernel proxy"
                         f"{' [returns FD]' if returns_fd else ''}")

    def _make_forwarder(self, name: str, guest_nr: int, returns_fd: bool):
        """Create a CALL hook closure for one syscall."""
        client = self._client

        def _forwarder(ql, *args):
            # use the HOST syscall number, not the guest number.
            # for now, resolve from the host's syscall table at runtime.
            host_nr = self._get_host_syscall_nr(name)

            padded = args + (0,) * (6 - len(args))
            retval = client.syscall(host_nr, padded[:6])

            if returns_fd and retval >= 0:
                # the proxy created a real FD. wrap it and store in Qiling's FD table.
                proxy_fd_obj = ql_proxy_fd(client, retval)
                guest_fd = self._alloc_fd(ql, proxy_fd_obj)
                ql.log.debug(f"kernel_proxy: {name}() -> proxy_fd={retval}, guest_fd={guest_fd}")
                return guest_fd

            ql.log.debug(f"kernel_proxy: {name}({', '.join(f'{a:#x}' for a in args)}) = {retval}")
            return retval

        _forwarder.__name__ = f'ql_syscall_{name}'
        return _forwarder

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
