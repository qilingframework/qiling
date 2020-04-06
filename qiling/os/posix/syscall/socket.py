#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)
import struct
import sys
import os
import stat
import string
import resource
import socket
import time
import io
import select
import pathlib
import logging
import itertools

# Remove import fcntl due to Windows Limitation
#import fcntl

from unicorn import *
from unicorn.arm_const import *
from unicorn.x86_const import *
from unicorn.arm64_const import *
from unicorn.mips_const import *

# impport read_string and other commom utils.
from qiling.os.utils import *
from qiling.const import *
from qiling.os.linux.thread import *
from qiling.const import *
from qiling.os.posix.filestruct import *
from qiling.os.posix.const_mapping import *
from qiling.utils import *

def ql_syscall_socket(ql, socket_domain, socket_type, socket_protocol, *args, **kw):
    if ql.arch == QL_MIPS32 and socket_type == 2:
        socket_type = 1
    elif ql.arch == QL_MIPS32 and socket_type == 1:
        socket_type = 1

    idx = -1
    for i in range(256):
        if ql.file_des[i] == 0:
            idx = i
            break
    try:
        if idx == -1:
            regreturn = -1
        else:
            if ql.output == QL_OUT_DEBUG: # set REUSEADDR options under debug mode
                ql.file_des[idx] = ql_socket.open(socket_domain, socket_type, socket_protocol, (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1))
            else:
                ql.file_des[idx] = ql_socket.open(socket_domain, socket_type, socket_protocol)

            regreturn = (idx)
    except:
        regreturn = -1

    ql.nprint("socket(%d, %d, %d) = %d" % (socket_domain, socket_type, socket_protocol, regreturn))

    socket_type = socket_type_mapping(socket_type, ql.arch)
    socket_domain = socket_domain_mapping(socket_domain, ql.arch)
    ql.dprint(1, "[+] socket(%s, %s, %s) = %d" % (socket_domain, socket_type, socket_protocol, regreturn))

    ql_definesyscall_return(ql, regreturn)


def ql_syscall_connect(ql, connect_sockfd, connect_addr, connect_addrlen, *args, **kw):
    AF_UNIX = 1
    AF_INET = 2
    sock_addr = ql.mem.read(connect_addr, connect_addrlen)
    family = ql.unpack16(sock_addr[ : 2])
    s = ql.file_des[connect_sockfd]
    ip = b''
    sun_path = b''
    port = 0
    try:
        if s.family == family:
            if s.family == AF_UNIX:
                sun_path = sock_addr[2 : ].split(b"\x00")[0]
                sun_path = ql_transform_to_real_path(ql, sun_path.decode())
                s.connect(sun_path)
                regreturn = 0
            elif s.family == AF_INET:
                port, host = struct.unpack(">HI", sock_addr[2:8])
                ip = ql_bin_to_ip(host)
                s.connect((ip, port))
                regreturn = 0
            else:
                regreturn = -1
        else:
            regreturn = -1
    except:
        regreturn = -1

    if s.family == AF_UNIX:
        ql.nprint("connect(%s) = %d" % (sun_path, regreturn))
    elif s.family == AF_INET:
        ql.nprint("connect(%s, %d) = %d" % (ip, port, regreturn))
    else:
        ql.nprint("connect() = %d" % (regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_setsockopt(ql, *args, **kw):
    ql.nprint("setsockopt")
    regreturn = 0
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_shutdown(ql, shutdown_fd, shutdown_how, *args, **kw):
    ql.nprint("shutdown(%d, %d)" % (shutdown_fd, shutdown_how))
    if shutdown_fd >=0 and shutdown_fd < 256 and ql.file_des[shutdown_fd] != 0:
        try:
            ql.file_des[shutdown_fd].shutdown(shutdown_how)
            regreturn = 0
        except:
            regreturn = -1
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_bind(ql, bind_fd, bind_addr, bind_addrlen,  *args, **kw):
    regreturn = 0

    if ql.arch == QL_X8664:
        data = ql.mem.read(bind_addr, 8)
    else:
        data = ql.mem.read(bind_addr, bind_addrlen)

    sin_family, = struct.unpack("<h", data[:2])
    port, host = struct.unpack(">HI", data[2:8])
    host = ql_bin_to_ip(host)

    if ql.root == False and port <= 1024:
        port = port + 8000

    if sin_family == 1:
        path = data[2 : ].split(b'\x00')[0]
        path = ql_transform_to_real_path(ql, path.decode())
        ql.nprint(path)
        ql.file_des[bind_fd].bind(path)

    # need a proper fix, for now ipv4 comes first
    elif sin_family == 2 and ql.bindtolocalhost == True:
        ql.file_des[bind_fd].bind(('127.0.0.1', port))
        host = "127.0.0.1"

    # IPv4 should comes first
    elif ql.ipv6 == True and sin_family == 10 and ql.bindtolocalhost == True:
        ql.file_des[bind_fd].bind(('::1', port))
        host = "::1"

    elif ql.bindtolocalhost == False:
        ql.file_des[bind_fd].bind((host, port))

    else:
        regreturn = -1

    if ql.shellcoder:
        regreturn = 0

    if sin_family == 1:
        ql.nprint("bind(%d, %s, %d) = %d" % (bind_fd, path, bind_addrlen, regreturn))
    else:
        ql.nprint("bind(%d,%s:%d,%d) = %d" % (bind_fd, host, port, bind_addrlen,regreturn))
        ql.dprint (0, "[+] syscall bind host: %s and port: %i sin_family: %i" % (ql_bin_to_ip(host), port, sin_family))

    ql_definesyscall_return(ql, regreturn)


def ql_syscall_listen(ql, listen_sockfd, listen_backlog, *args, **kw):
    if listen_sockfd < 256 and ql.file_des[listen_sockfd] != 0:
        try:
            ql.file_des[listen_sockfd].listen(listen_backlog)
            regreturn = 0
        except:
            if ql.output == QL_OUT_DEBUG:
                raise
            regreturn = -1
    else:
        regreturn = -1
    ql.nprint("listen(%d, %d) = %d" % (listen_sockfd, listen_backlog, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_accept(ql, accept_sockfd, accept_addr, accept_addrlen, *args, **kw):
    def inet_addr(ip):
        ret = b''
        tmp = ip.split('.')
        if len(tmp) != 4:
            return ret
        for i in tmp[ : : -1]:
            ret += bytes([int(i)])
        return ret
    try:
        conn, address = ql.file_des[accept_sockfd].accept()
        idx = -1
        for i in range(256):
            if ql.file_des[i] == 0:
                idx = i
                break
        if idx == -1:
            regreturn = -1
        else:
            ql.file_des[idx] = conn
            regreturn = idx

        if ql.shellcoder == None:
            tmp_buf = ql.pack16(conn.family)
            tmp_buf += ql.pack16(address[1])
            tmp_buf += inet_addr(address[0])
            tmp_buf += b'\x00' * 8
            ql.mem.write(accept_addr, tmp_buf)
            ql.mem.write(accept_addrlen, ql.pack32(16))
    except:
        if ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
            raise
        regreturn = -1
    ql.nprint("accep(%d, %x, %x) = %d" %(accept_sockfd, accept_addr, accept_addrlen, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_recv(ql, recv_sockfd, recv_buf, recv_len, recv_flags, *args, **kw):
    if recv_sockfd < 256 and ql.file_des[recv_sockfd] != 0:
        tmp_buf = ql.file_des[recv_sockfd].recv(recv_len, recv_flags)
        if tmp_buf:
            ql.dprint(1, "[+] recv() CONTENT:")
            ql.dprint(1, "%s" % tmp_buf)
        ql.mem.write(recv_buf, tmp_buf)
        regreturn = len(tmp_buf)
    else:
        regreturn = -1
    ql.nprint("recv(%d, %x, %d, %x) = %d" % (recv_sockfd, recv_buf, recv_len, recv_flags, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_send(ql, send_sockfd, send_buf, send_len, send_flags, *args, **kw):
    regreturn = 0
    if send_sockfd < 256 and ql.file_des[send_sockfd] != 0:
        try:
            ql.dprint(1, "[+] debug send() start")
            tmp_buf = ql.mem.read(send_buf, send_len)
            ql.dprint(1, ql.file_des[send_sockfd])
            ql.dprint(1, "[+] fd is " + str(send_sockfd))
            ql.dprint(1, "[+] send() CONTENT:")
            ql.dprint(1, "%s" % tmp_buf)
            ql.dprint(1, "[+] send() flag is " + str(send_flags))
            ql.dprint(1, "[+] send() len is " + str(send_len))
            ql.file_des[send_sockfd].send(bytes(tmp_buf), send_flags)
            ql.dprint(ql.file_des[send_sockfd])
            regreturn = send_len
            ql.dprint(1, "[+] debug send end")
        except:
            print(sys.exc_info()[0])
            if ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
                raise
    else:
        regreturn = -1
    ql.nprint("send(%d, %x, %d, %x) = %d" % (send_sockfd, send_buf, send_len, send_flags, regreturn))
    ql_definesyscall_return(ql, regreturn)
