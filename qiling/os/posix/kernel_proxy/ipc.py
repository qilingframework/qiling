#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

"""
IPC protocol between Qiling and the kernel proxy process.

Three message types:
  SYSCALL    — forward a raw syscall (number + 6 integer args, no buffers)
  SYSCALL_EX — forward a syscall with input/output buffer marshaling
  FD_OP      — perform an operation on a proxy-side FD (read/write/close/dup/fcntl/ioctl)

All messages are length-prefixed binary over a Unix socketpair.
"""

import struct
import socket
from enum import IntEnum
from typing import List, Sequence, Tuple

from qiling.exception import QlProxyConnectionError


class MsgType(IntEnum):
    SYSCALL    = 1
    FD_OP      = 2
    SYSCALL_EX = 3


class FdOp(IntEnum):
    READ  = 1
    WRITE = 2
    CLOSE = 3
    DUP   = 4
    FCNTL = 5
    IOCTL = 6


# Wire format:
#   Request header:     [msg_type: u8][payload_len: u32]
#   SYSCALL payload:    [syscall_nr: u32][args: 6 x i64]
#   SYSCALL_EX payload: [syscall_nr: u32][args: 6 x i64]
#                       [num_in: u8] then num_in * [arg_idx: u8][len: u32][data: bytes]
#                       [num_out: u8] then num_out * [arg_idx: u8][len: u32]
#   FD_OP payload:      [op: u8][proxy_fd: i32][arg1: i64][arg2: i64][data_len: u32][data: bytes]
#
#   Response header: [status: i8][payload_len: u32]
#   status 0 = success, -1 = error
#   SYSCALL response payload:    [return_value: i64][errno: i32]
#   SYSCALL_EX response payload: [return_value: i64][errno: i32][num_out: u8]
#                                then num_out * [len: u32][data: bytes]
#   FD_OP response payload:      [return_value: i64][errno: i32][data_len: u32][data: bytes]

HEADER_FMT = '!BI'           # msg_type/status (u8) + payload_len (u32)
HEADER_SIZE = struct.calcsize(HEADER_FMT)

SYSCALL_REQ_FMT = '!I6q'     # syscall_nr (u32) + 6 args (i64)
SYSCALL_REQ_SIZE = struct.calcsize(SYSCALL_REQ_FMT)

SYSCALL_RESP_FMT = '!qi'     # return_value (i64) + errno (i32)
SYSCALL_RESP_SIZE = struct.calcsize(SYSCALL_RESP_FMT)

SYSCALL_EX_RESP_HEAD_FMT = '!qiB'   # return_value (i64) + errno (i32) + num_out (u8)
SYSCALL_EX_RESP_HEAD_SIZE = struct.calcsize(SYSCALL_EX_RESP_HEAD_FMT)

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
            raise QlProxyConnectionError("kernel proxy connection closed")
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

    def syscall_ex(self, nr: int, args: Sequence[int],
                   in_bufs: Sequence[Tuple[int, bytes]],
                   out_specs: Sequence[Tuple[int, int]]) -> Tuple[int, List[bytes]]:
        """Forward a syscall with buffer marshaling.

        Args:
            nr: host syscall number.
            args: 6 integer arg values; for buffer args these are placeholders —
                  the proxy replaces them with the buffer address before invoking.
            in_bufs: list of (arg_idx, data) — buffers to copy in.
            out_specs: list of (arg_idx, length) — buffers to copy out.

        Returns:
            (retval, out_bufs) where out_bufs is a list aligned with out_specs.
        """
        padded = tuple(args) + (0,) * (6 - len(args))
        payload = bytearray(struct.pack(SYSCALL_REQ_FMT, nr, *padded[:6]))

        payload.append(len(in_bufs))
        for arg_idx, data in in_bufs:
            payload += struct.pack('!BI', arg_idx, len(data))
            payload += data

        payload.append(len(out_specs))
        for arg_idx, length in out_specs:
            payload += struct.pack('!BI', arg_idx, length)

        header = struct.pack(HEADER_FMT, MsgType.SYSCALL_EX, len(payload))
        self._sock.sendall(header + bytes(payload))

        resp_header = _recvall(self._sock, HEADER_SIZE)
        _, resp_len = struct.unpack(HEADER_FMT, resp_header)
        resp_payload = _recvall(self._sock, resp_len)

        retval, _errno, num_out = struct.unpack(
            SYSCALL_EX_RESP_HEAD_FMT, resp_payload[:SYSCALL_EX_RESP_HEAD_SIZE]
        )

        out_bufs: List[bytes] = []
        offset = SYSCALL_EX_RESP_HEAD_SIZE
        for _ in range(num_out):
            (length,) = struct.unpack('!I', resp_payload[offset:offset + 4])
            offset += 4
            out_bufs.append(resp_payload[offset:offset + length])
            offset += length

        return retval, out_bufs

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

        elif msg_type == MsgType.SYSCALL_EX:
            offset = SYSCALL_REQ_SIZE
            fixed = struct.unpack(SYSCALL_REQ_FMT, payload[:offset])
            nr = fixed[0]
            args = list(fixed[1:])

            num_in = payload[offset]
            offset += 1
            in_bufs: List[Tuple[int, bytes]] = []
            for _ in range(num_in):
                arg_idx, length = struct.unpack('!BI', payload[offset:offset + 5])
                offset += 5
                in_bufs.append((arg_idx, payload[offset:offset + length]))
                offset += length

            num_out = payload[offset]
            offset += 1
            out_specs: List[Tuple[int, int]] = []
            for _ in range(num_out):
                arg_idx, length = struct.unpack('!BI', payload[offset:offset + 5])
                offset += 5
                out_specs.append((arg_idx, length))

            return MsgType.SYSCALL_EX, (nr, args, in_bufs, out_specs)

        elif msg_type == MsgType.FD_OP:
            fixed = struct.unpack(FD_OP_REQ_FMT, payload[:FD_OP_REQ_SIZE])
            op, proxy_fd, arg1, arg2, data_len = fixed
            data = payload[FD_OP_REQ_SIZE:FD_OP_REQ_SIZE + data_len]
            return MsgType.FD_OP, (FdOp(op), proxy_fd, arg1, arg2, data)

        else:
            raise QlProxyConnectionError(f"unknown message type: {msg_type}")

    def send_syscall_response(self, retval: int, errno_val: int):
        payload = struct.pack(SYSCALL_RESP_FMT, retval, errno_val)
        header = struct.pack(HEADER_FMT, 0, len(payload))
        self._sock.sendall(header + payload)

    def send_syscall_ex_response(self, retval: int, errno_val: int, out_bufs: Sequence[bytes]):
        payload = bytearray(struct.pack(SYSCALL_EX_RESP_HEAD_FMT, retval, errno_val, len(out_bufs)))
        for buf in out_bufs:
            payload += struct.pack('!I', len(buf))
            payload += buf

        header = struct.pack(HEADER_FMT, 0, len(payload))
        self._sock.sendall(header + bytes(payload))

    def send_fd_op_response(self, retval: int, errno_val: int, data: bytes = b''):
        payload = struct.pack(FD_OP_RESP_FMT, retval, errno_val, len(data))
        payload += data
        header = struct.pack(HEADER_FMT, 0, len(payload))
        self._sock.sendall(header + payload)
