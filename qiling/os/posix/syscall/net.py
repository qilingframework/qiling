#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

from qiling.const import *
from qiling.os.linux.thread import *
from qiling.const import *
from qiling.os.posix.filestruct import *
from qiling.os.filestruct import *
from qiling.os.posix.const_mapping import *
from qiling.exception import *

from qiling.os.posix.syscall.socket import ql_syscall_socket, ql_syscall_connect, ql_syscall_recv, ql_syscall_bind, ql_syscall_listen, ql_syscall_accept, ql_syscall_setsockopt

def ql_syscall_socketcall(ql, socketcall_call, socketcall_args, *args, **kw):
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

    ql.nprint("socketcall(%d, %x)" % (socketcall_call, socketcall_args))

    if socketcall_call == SOCKETCALL_SYS_SOCKET:
        socketcall_domain = ql.unpack(ql.mem.read(socketcall_args, ql.pointersize))
        socketcall_type = ql.unpack(ql.mem.read(socketcall_args + ql.pointersize, ql.pointersize))
        socketcall_protocol = ql.unpack(ql.mem.read(socketcall_args + ql.pointersize * 2, ql.pointersize))
        ql_syscall_socket(ql, socketcall_domain, socketcall_type, socketcall_protocol, 0, 0, 0)
    
    elif socketcall_call == SOCKETCALL_SYS_CONNECT:
        socketcall_sockfd = ql.unpack(ql.mem.read(socketcall_args, ql.pointersize))
        socketcall_addr = ql.unpack(ql.mem.read(socketcall_args + ql.pointersize, ql.pointersize))
        socketcall_addrlen = ql.unpack(ql.mem.read(socketcall_args + ql.pointersize * 2, ql.pointersize))
        ql_syscall_connect(ql, socketcall_sockfd, socketcall_addr, socketcall_addrlen, 0, 0, 0)
    
    elif socketcall_call == SOCKETCALL_SYS_RECV:
        socketcall_sockfd = ql.unpack(ql.mem.read(socketcall_args, ql.pointersize))
        socketcall_buf = ql.unpack(ql.mem.read(socketcall_args + ql.pointersize, ql.pointersize))
        socketcall_len = ql.unpack(ql.mem.read(socketcall_args + ql.pointersize * 2, ql.pointersize))
        socketcall_flags = ql.unpack(ql.mem.read(socketcall_args + ql.pointersize * 3, ql.pointersize))
        ql_syscall_recv(ql, socketcall_sockfd, socketcall_buf, socketcall_len, socketcall_flags, 0, 0)
    
    elif socketcall_call == SOCKETCALL_SYS_BIND:
        socketcall_fd = ql.unpack(ql.mem.read(socketcall_args, ql.pointersize))
        socketcall_addr = ql.unpack(ql.mem.read(socketcall_args + ql.pointersize, ql.pointersize))
        socketcall_addrlen = ql.unpack(ql.mem.read(socketcall_args + ql.pointersize * 2, ql.pointersize))
        ql_syscall_bind(ql, socketcall_fd, socketcall_addr, socketcall_addrlen)
    
    elif socketcall_call == SOCKETCALL_SYS_LISTEN:
        socketcall_sockfd = ql.unpack(ql.mem.read(socketcall_args, ql.pointersize))
        socketcall_backlog = ql.unpack(ql.mem.read(socketcall_args + ql.pointersize, ql.pointersize))
        ql_syscall_listen(ql, socketcall_sockfd, socketcall_backlog)
    
    elif socketcall_call == SOCKETCALL_SYS_ACCEPT:
        socketcall_sockfd = ql.unpack(ql.mem.read(socketcall_args, ql.pointersize))
        socketcall_addr = ql.unpack(ql.mem.read(socketcall_args + ql.pointersize, ql.pointersize))
        socketcall_addrlen = ql.unpack(ql.mem.read(socketcall_args + ql.pointersize * 2, ql.pointersize))
        ql_syscall_accept(ql, socketcall_sockfd, socketcall_addr, socketcall_addrlen)
    
    elif socketcall_call == SOCKETCALL_SYS_SETSOCKOPT:
        ql_syscall_setsockopt(ql)
    
    else:
        ql.dprint(D_INFO, "[!] error call %d" % socketcall_call)
        ql.os.stop(stop_event=THREAD_EVENT_UNEXECPT_EVENT)
        raise