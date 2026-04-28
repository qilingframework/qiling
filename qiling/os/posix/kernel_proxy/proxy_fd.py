#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

"""
Proxy file descriptor — wraps an FD that lives in the kernel proxy process.

When a forwarded syscall returns an FD (e.g. epoll_create, eventfd), the real
FD lives in the proxy. This wrapper forwards read/write/close to the proxy via
IPC, matching the interface of ql_socket and ql_pipe so existing syscall handlers
(ql_syscall_read, ql_syscall_write, ql_syscall_close) work without modification.
"""

from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from qiling.os.posix.kernel_proxy.ipc import ProxyClient


class ql_proxy_fd:
    def __init__(self, client: ProxyClient, proxy_fd: int):
        self._client = client
        self._proxy_fd = proxy_fd

    def read(self, length: int) -> bytes:
        return self._client.fd_read(self._proxy_fd, length)

    def write(self, data: bytes) -> int:
        return self._client.fd_write(self._proxy_fd, data)

    def close(self) -> None:
        self._client.fd_close(self._proxy_fd)

    def fileno(self) -> int:
        return -1

    def dup(self) -> ql_proxy_fd:
        new_proxy_fd = self._client.fd_dup(self._proxy_fd)
        return ql_proxy_fd(self._client, new_proxy_fd)

    def fcntl(self, cmd, arg):
        return self._client.fd_fcntl(self._proxy_fd, cmd, arg)

    def ioctl(self, cmd, arg):
        return self._client.fd_ioctl(self._proxy_fd, cmd, arg)
