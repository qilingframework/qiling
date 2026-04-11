#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

"""
IPC protocol between Qiling and the kernel proxy process.

Two message types:
  SYSCALL  — forward a raw syscall (number + 6 integer args)
  FD_OP    — perform an operation on a proxy-side FD (read/write/close/dup/fcntl/ioctl)

All messages are length-prefixed binary over a Unix socketpair.
"""

import struct
import socket
from enum import IntEnum


class MsgType(IntEnum):
    SYSCALL = 1
    FD_OP   = 2


class FdOp(IntEnum):
    READ  = 1
    WRITE = 2
    CLOSE = 3
    DUP   = 4
    FCNTL = 5
    IOCTL = 6


# Wire format:
#   Request header:  [msg_type: u8][payload_len: u32]
#   SYSCALL payload: [syscall_nr: u32][args: 6 x i64]
#   FD_OP payload:   [op: u8][proxy_fd: i32][arg1: i64][arg2: i64][data_len: u32][data: bytes]
#
#   Response header: [status: i8][payload_len: u32]
#   status 0 = success, -1 = error
#   SYSCALL response payload: [return_value: i64][errno: i32]
#   FD_OP response payload:   [return_value: i64][errno: i32][data_len: u32][data: bytes]

HEADER_FMT = '!BI'           # msg_type/status (u8) + payload_len (u32)
HEADER_SIZE = struct.calcsize(HEADER_FMT)

SYSCALL_REQ_FMT = '!I6q'     # syscall_nr (u32) + 6 args (i64)
SYSCALL_REQ_SIZE = struct.calcsize(SYSCALL_REQ_FMT)

SYSCALL_RESP_FMT = '!qi'     # return_value (i64) + errno (i32)
SYSCALL_RESP_SIZE = struct.calcsize(SYSCALL_RESP_FMT)

FD_OP_REQ_FMT = '!BiqqI'    # op (u8) + proxy_fd (i32) + arg1 (i64) + arg2 (i64) + data_len (u32)
FD_OP_REQ_SIZE = struct.calcsize(FD_OP_REQ_FMT)

FD_OP_RESP_FMT = '!qiI'     # return_value (i64) + errno (i32) + data_len (u32)
FD_OP_RESP_SIZE = struct.calcsize(FD_OP_RESP_FMT)


def _recvall(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes from a socket."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("kernel proxy connection closed")
        buf.extend(chunk)
    return bytes(buf)


class ProxyClient:
    """Qiling-side IPC client — sends requests to the proxy process."""

    def __init__(self, sock: socket.socket):
        self._sock = sock

    def syscall(self, nr: int, args: tuple) -> int:
        """Forward a raw syscall. Returns kernel-convention result (negative errno on error)."""
        padded = tuple(args) + (0,) * (6 - len(args))
        payload = struct.pack(SYSCALL_REQ_FMT, nr, *padded[:6])

        # send request
        header = struct.pack(HEADER_FMT, MsgType.SYSCALL, len(payload))
        self._sock.sendall(header + payload)

        # recv response
        resp_header = _recvall(self._sock, HEADER_SIZE)
        _, resp_len = struct.unpack(HEADER_FMT, resp_header)
        resp_payload = _recvall(self._sock, resp_len)

        retval, errno_val = struct.unpack(SYSCALL_RESP_FMT, resp_payload)
        return retval

    def _fd_op(self, op: FdOp, proxy_fd: int, arg1: int = 0, arg2: int = 0, data: bytes = b'') -> tuple:
        """Send an FD operation. Returns (return_value, data)."""
        payload = struct.pack(FD_OP_REQ_FMT, op, proxy_fd, arg1, arg2, len(data))
        payload += data

        header = struct.pack(HEADER_FMT, MsgType.FD_OP, len(payload))
        self._sock.sendall(header + payload)

        resp_header = _recvall(self._sock, HEADER_SIZE)
        _, resp_len = struct.unpack(HEADER_FMT, resp_header)
        resp_payload = _recvall(self._sock, resp_len)

        retval, errno_val, data_len = struct.unpack(FD_OP_RESP_FMT, resp_payload[:FD_OP_RESP_SIZE])
        resp_data = resp_payload[FD_OP_RESP_SIZE:FD_OP_RESP_SIZE + data_len]

        return retval, resp_data

    def fd_read(self, proxy_fd: int, length: int) -> bytes:
        retval, data = self._fd_op(FdOp.READ, proxy_fd, arg1=length)
        if retval < 0:
            return b''
        return data

    def fd_write(self, proxy_fd: int, data: bytes) -> int:
        retval, _ = self._fd_op(FdOp.WRITE, proxy_fd, data=data)
        return retval

    def fd_close(self, proxy_fd: int) -> None:
        self._fd_op(FdOp.CLOSE, proxy_fd)

    def fd_dup(self, proxy_fd: int) -> int:
        retval, _ = self._fd_op(FdOp.DUP, proxy_fd)
        return retval

    def fd_fcntl(self, proxy_fd: int, cmd: int, arg: int) -> int:
        retval, _ = self._fd_op(FdOp.FCNTL, proxy_fd, arg1=cmd, arg2=arg)
        return retval

    def fd_ioctl(self, proxy_fd: int, cmd: int, arg: int) -> int:
        retval, _ = self._fd_op(FdOp.IOCTL, proxy_fd, arg1=cmd, arg2=arg)
        return retval

    def close(self):
        self._sock.close()


class ProxyServer:
    """Proxy-side IPC server — receives requests, executes real syscalls."""

    def __init__(self, sock: socket.socket):
        self._sock = sock

    def recv_request(self) -> tuple:
        """Receive one request. Returns (msg_type, parsed_fields)."""
        header = _recvall(self._sock, HEADER_SIZE)
        msg_type, payload_len = struct.unpack(HEADER_FMT, header)

        payload = _recvall(self._sock, payload_len)

        if msg_type == MsgType.SYSCALL:
            fields = struct.unpack(SYSCALL_REQ_FMT, payload)
            return MsgType.SYSCALL, fields  # (nr, a0, a1, a2, a3, a4, a5)

        elif msg_type == MsgType.FD_OP:
            fixed = struct.unpack(FD_OP_REQ_FMT, payload[:FD_OP_REQ_SIZE])
            op, proxy_fd, arg1, arg2, data_len = fixed
            data = payload[FD_OP_REQ_SIZE:FD_OP_REQ_SIZE + data_len]
            return MsgType.FD_OP, (FdOp(op), proxy_fd, arg1, arg2, data)

        else:
            raise ValueError(f"unknown message type: {msg_type}")

    def send_syscall_response(self, retval: int, errno_val: int):
        payload = struct.pack(SYSCALL_RESP_FMT, retval, errno_val)
        header = struct.pack(HEADER_FMT, 0, len(payload))
        self._sock.sendall(header + payload)

    def send_fd_op_response(self, retval: int, errno_val: int, data: bytes = b''):
        payload = struct.pack(FD_OP_RESP_FMT, retval, errno_val, len(data))
        payload += data
        header = struct.pack(HEADER_FMT, 0, len(payload))
        self._sock.sendall(header + payload)
