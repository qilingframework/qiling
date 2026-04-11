#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

"""
Kernel proxy process — executes real Linux syscalls on behalf of Qiling.

This runs as a subprocess. It receives syscall requests over a Unix socketpair,
executes them via libc.syscall(), and sends back results.

Usage (internal — started by KernelProxy.__init__):
    python -m qiling.os.posix.kernel_proxy.proxy <socket_fd>
"""

import os
import sys
import ctypes
import ctypes.util
import errno as errno_module
import socket

from qiling.os.posix.kernel_proxy.ipc import (
    ProxyServer, MsgType, FdOp
)

# load libc for raw syscall()
_libc_path = ctypes.util.find_library("c")
if _libc_path is None:
    print("kernel_proxy: cannot find libc", file=sys.stderr)
    sys.exit(1)

_libc = ctypes.CDLL(_libc_path, use_errno=True)
_libc.syscall.restype = ctypes.c_long
_libc.syscall.argtypes = [ctypes.c_long] + [ctypes.c_long] * 6


def raw_syscall(nr: int, a0: int, a1: int, a2: int, a3: int, a4: int, a5: int) -> tuple:
    """Execute a real Linux syscall. Returns (return_value, errno) in kernel convention."""
    ctypes.set_errno(0)
    result = _libc.syscall(nr, a0, a1, a2, a3, a4, a5)

    if result == -1:
        err = ctypes.get_errno()
        if err != 0:
            return -err, err  # kernel convention: negative errno

    return result, 0


def handle_fd_op(op: FdOp, proxy_fd: int, arg1: int, arg2: int, data: bytes) -> tuple:
    """Handle an FD operation on a proxy-side FD. Returns (retval, errno, data)."""
    try:
        if op == FdOp.READ:
            result = os.read(proxy_fd, arg1)
            return len(result), 0, result

        elif op == FdOp.WRITE:
            written = os.write(proxy_fd, data)
            return written, 0, b''

        elif op == FdOp.CLOSE:
            os.close(proxy_fd)
            return 0, 0, b''

        elif op == FdOp.DUP:
            new_fd = os.dup(proxy_fd)
            return new_fd, 0, b''

        elif op == FdOp.FCNTL:
            import fcntl
            result = fcntl.fcntl(proxy_fd, arg1, arg2)
            return result, 0, b''

        elif op == FdOp.IOCTL:
            import fcntl
            result = fcntl.ioctl(proxy_fd, arg1, arg2)
            return result, 0, b''

        else:
            return -errno_module.ENOSYS, errno_module.ENOSYS, b''

    except OSError as e:
        return -e.errno, e.errno, b''


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <socket_fd>", file=sys.stderr)
        sys.exit(1)

    sock_fd = int(sys.argv[1])
    sock = socket.socket(fileno=sock_fd)
    server = ProxyServer(sock)

    while True:
        try:
            msg_type, fields = server.recv_request()
        except ConnectionError:
            break

        if msg_type == MsgType.SYSCALL:
            nr, a0, a1, a2, a3, a4, a5 = fields
            retval, err = raw_syscall(nr, a0, a1, a2, a3, a4, a5)
            server.send_syscall_response(retval, err)

        elif msg_type == MsgType.FD_OP:
            op, proxy_fd, arg1, arg2, data = fields
            retval, err, resp_data = handle_fd_op(op, proxy_fd, arg1, arg2, data)
            server.send_fd_op_response(retval, err, resp_data)

    sock.close()


if __name__ == '__main__':
    main()
