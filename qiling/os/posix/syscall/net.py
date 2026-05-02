#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import inspect
from enum import IntEnum
from typing import Callable, Mapping

from qiling import Qiling
from qiling.os.posix.syscall.socket import *


class SOCKETCALL(IntEnum):
    SYS_SOCKET = 1
    SYS_BIND = 2
    SYS_CONNECT = 3
    SYS_LISTEN = 4
    SYS_ACCEPT = 5
    SYS_GETSOCKNAME = 6
    SYS_GETPEERNAME = 7
    SYS_SOCKETPAIR = 8
    SYS_SEND = 9
    SYS_RECV = 10
    SYS_SENDTO = 11
    SYS_RECVFROM = 12
    SYS_SHUTDOWN = 13
    SYS_SETSOCKOPT = 14
    SYS_GETSOCKOPT = 15
    SYS_SENDMSG = 16
    SYS_RECVMSG = 17
    SYS_ACCEPT4 = 18
    SYS_RECVMMSG = 19
    SYS_SENDMMSG = 20


def ql_syscall_socketcall(ql: Qiling, call: int, args: int):
    # map call values to their corresponding handlers
    handlers: Mapping[SOCKETCALL, Callable] = {
        SOCKETCALL.SYS_SOCKET:      ql_syscall_socket,
        SOCKETCALL.SYS_BIND:        ql_syscall_bind,
        SOCKETCALL.SYS_CONNECT:     ql_syscall_connect,
        SOCKETCALL.SYS_LISTEN:      ql_syscall_listen,
        SOCKETCALL.SYS_ACCEPT:      ql_syscall_accept,
        SOCKETCALL.SYS_GETSOCKNAME: ql_syscall_getsockname,
        SOCKETCALL.SYS_GETPEERNAME: ql_syscall_getpeername,
        SOCKETCALL.SYS_SOCKETPAIR:  ql_syscall_socketpair,
        SOCKETCALL.SYS_SEND:        ql_syscall_send,
        SOCKETCALL.SYS_RECV:        ql_syscall_recv,
        SOCKETCALL.SYS_SENDTO:      ql_syscall_sendto,
        SOCKETCALL.SYS_RECVFROM:    ql_syscall_recvfrom,
        SOCKETCALL.SYS_SHUTDOWN:    ql_syscall_shutdown,
        SOCKETCALL.SYS_SETSOCKOPT:  ql_syscall_setsockopt,
        SOCKETCALL.SYS_GETSOCKOPT:  ql_syscall_getsockopt,
        SOCKETCALL.SYS_RECVMSG:     ql_syscall_recvmsg
    }

    if call not in handlers:
        call_name = next((m.name for m in SOCKETCALL if m.value == call), '')

        raise NotImplementedError(f'socketcall: call {call_name or call} not implemented')

    handler = handlers[call]

    # determine number of arguments, excluding the first 'ql' arg
    nargs = len(inspect.signature(handler).parameters) - 1

    # read 'nargs' arguments from the specified base pointer 'args'
    params = (ql.mem.read_ptr(args + i * ql.arch.pointersize) for i in range(nargs))

    return handler(ql, *params)
