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

import logging
import os
import sys
import ctypes
import ctypes.util
import errno as errno_module
import socket

from qiling.os.posix.kernel_proxy.ipc import (
    ProxyServer, MsgType, FdOp
)

log = logging.getLogger("qiling.os.posix.kernel_proxy.proxy")

# load libc for raw syscall()
_libc_path = ctypes.util.find_library("c")
if _libc_path is None:
    log.critical("kernel_proxy: cannot find libc")
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


def raw_syscall_ex(nr: int, args: list, in_bufs: list, out_specs: list) -> tuple:
    """Execute a syscall with buffer marshaling.

    For each in_buf (arg_idx, data): allocate a ctypes buffer initialized with
    data and place its address in args[arg_idx]. For each out_spec (arg_idx, length):
    allocate a zeroed buffer and place its address in args[arg_idx]. After the
    syscall, return the contents of each out buffer.
    """
    keepalive = []  # keep ctypes buffers alive until after the syscall
    out_buffers = []  # parallel to out_specs

    args = list(args)

    for arg_idx, data in in_bufs:
        buf = ctypes.create_string_buffer(data, len(data))
        keepalive.append(buf)
        args[arg_idx] = ctypes.addressof(buf)

    for arg_idx, length in out_specs:
        buf = ctypes.create_string_buffer(length)
        keepalive.append(buf)
        out_buffers.append(buf)
        args[arg_idx] = ctypes.addressof(buf)

    retval, err = raw_syscall(nr, *args)

    out_data = [bytes(buf.raw) for buf in out_buffers]
    return retval, err, out_data


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
        log.error(f"usage: {sys.argv[0]} <socket_fd>")
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

        elif msg_type == MsgType.SYSCALL_EX:
            nr, args, in_bufs, out_specs = fields
            retval, err, out_bufs = raw_syscall_ex(nr, args, in_bufs, out_specs)
            server.send_syscall_ex_response(retval, err, out_bufs)

        elif msg_type == MsgType.FD_OP:
            op, proxy_fd, arg1, arg2, data = fields
            retval, err, resp_data = handle_fd_op(op, proxy_fd, arg1, arg2, data)
            server.send_fd_op_response(retval, err, resp_data)

    sock.close()


if __name__ == '__main__':
    main()
