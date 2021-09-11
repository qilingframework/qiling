#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Callable, Mapping, Tuple

from qiling import Qiling
from qiling.os.posix.syscall.socket import ql_syscall_socket, ql_syscall_connect, ql_syscall_recv, ql_syscall_send, ql_syscall_bind, ql_syscall_listen, ql_syscall_accept, ql_syscall_getsockname, ql_syscall_setsockopt, ql_syscall_recvfrom, ql_syscall_sendto

def ql_syscall_socketcall(ql: Qiling, call: int, args: int):
    SOCKETCALL_SYS_SOCKET = 1
    SOCKETCALL_SYS_BIND = 2
    SOCKETCALL_SYS_CONNECT = 3
    SOCKETCALL_SYS_LISTEN = 4
    SOCKETCALL_SYS_ACCEPT = 5
    SOCKETCALL_SYS_GETSOCKNAME = 6 
    SOCKETCALL_SYS_GETPEERNAME = 7
    SOCKETCALL_SYS_SOCKETPAIR = 8
    SOCKETCALL_SYS_SEND = 9
    SOCKETCALL_SYS_RECV = 10
    SOCKETCALL_SYS_SENDTO = 11
    SOCKETCALL_SYS_RECVFROM = 12
    SOCKETCALL_SYS_SHUTDOWN = 13
    SOCKETCALL_SYS_SETSOCKOPT = 14
    SOCKETCALL_SYS_GETSOCKOPT = 15
    SOCKETCALL_SYS_SENDMSG = 16
    SOCKETCALL_SYS_RECVMSG = 17
    SOCKETCALL_SYS_ACCEPT4 = 18
    SOCKETCALL_SYS_RECVMMSG = 19
    SOCKETCALL_SYS_SENDMMSG = 20

    # map call values to their corresponding handlers and number of arguments they
    # should read from the specified base pointer
    handlers: Mapping[int, Tuple[Callable, int]] = {
        SOCKETCALL_SYS_SOCKET      : (ql_syscall_socket, 3),
        SOCKETCALL_SYS_CONNECT     : (ql_syscall_connect, 3),
        SOCKETCALL_SYS_SEND        : (ql_syscall_send, 4),
        SOCKETCALL_SYS_RECVFROM    : (ql_syscall_recvfrom, 6),
        SOCKETCALL_SYS_SENDTO      : (ql_syscall_sendto, 6),
        SOCKETCALL_SYS_RECV        : (ql_syscall_recv, 4),
        SOCKETCALL_SYS_BIND        : (ql_syscall_bind, 3),
        SOCKETCALL_SYS_LISTEN      : (ql_syscall_listen, 2),
        SOCKETCALL_SYS_ACCEPT      : (ql_syscall_accept, 3),
        SOCKETCALL_SYS_GETSOCKNAME : (ql_syscall_getsockname, 3),
        SOCKETCALL_SYS_SETSOCKOPT  : (ql_syscall_setsockopt, 5)
    }

    if call not in handlers:
        ql.log.debug(f'socketcall: call {call:d} not implemented')
        ql.os.stop()
        raise

    handler, nargs = handlers[call]

    # read 'nargs' arguments from the specified base pointer 'args'
    params = (ql.unpack(ql.mem.read(args + i * ql.pointersize, ql.pointersize)) for i in range(nargs))

    return handler(ql, *params)
