#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import struct, ipaddress

from qiling.const import *
from qiling.os.linux.thread import *
from qiling.const import *
from qiling.os.posix.filestruct import *
from qiling.os.filestruct import *
from qiling.os.posix.const_mapping import *
from qiling.exception import *


def ql_bin_to_ip(ip):
    return ipaddress.ip_address(ip).compressed


def ql_syscall_socket(ql, socket_domain, socket_type, socket_protocol, *args, **kw):
    if ql.archtype== QL_ARCH.MIPS and socket_type == 2:
        socket_type = 1
    elif ql.archtype== QL_ARCH.MIPS and socket_type == 1:
        socket_type = 1

    idx = -1
    for i in range(256):
        if ql.os.file_des[i] == 0:
            idx = i
            break
    try:
        if idx == -1:
            regreturn = -1
        else:
            if ql.output == QL_OUTPUT.DEBUG: # set REUSEADDR options under debug mode
                ql.os.file_des[idx] = ql_socket.open(socket_domain, socket_type, socket_protocol, (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1))
            else:
                ql.os.file_des[idx] = ql_socket.open(socket_domain, socket_type, socket_protocol)

            regreturn = (idx)
    except:
        regreturn = -1

    ql.nprint("socket(%d, %d, %d) = %d" % (socket_domain, socket_type, socket_protocol, regreturn))


    socket_type = socket_type_mapping(socket_type, ql.archtype)
    socket_domain = socket_domain_mapping(socket_domain, ql.archtype)
    ql.dprint(D_INFO, "[+] socket(%s, %s, %s) = %d" % (socket_domain, socket_type, socket_protocol, regreturn))

    ql.os.definesyscall_return(regreturn)


def ql_syscall_connect(ql, connect_sockfd, connect_addr, connect_addrlen, *args, **kw):
    AF_UNIX = 1
    AF_INET = 2
    sock_addr = ql.mem.read(connect_addr, connect_addrlen)
    family = ql.unpack16(sock_addr[ : 2])
    s = ql.os.file_des[connect_sockfd]
    ip = b''
    sun_path = b''
    port = 0
    try:
        if s.family == family:
            if s.family == AF_UNIX:
                sun_path = sock_addr[2 : ].split(b"\x00")[0]
                sun_path = ql.os.transform_to_real_path(sun_path.decode())
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
    ql.os.definesyscall_return(regreturn)


def ql_syscall_setsockopt(ql, *args, **kw):
    ql.nprint("setsockopt")
    regreturn = 0
    ql.os.definesyscall_return(regreturn)


def ql_syscall_shutdown(ql, shutdown_fd, shutdown_how, *args, **kw):
    ql.nprint("shutdown(%d, %d)" % (shutdown_fd, shutdown_how))
    if shutdown_fd >=0 and shutdown_fd < 256 and ql.os.file_des[shutdown_fd] != 0:
        try:
            ql.os.file_des[shutdown_fd].shutdown(shutdown_how)
            regreturn = 0
        except:
            regreturn = -1
    ql.os.definesyscall_return(regreturn)


def ql_syscall_bind(ql, bind_fd, bind_addr, bind_addrlen,  *args, **kw):
    regreturn = 0

    if ql.archtype== QL_ARCH.X8664:
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
        path = ql.os.transform_to_real_path(path.decode())
        ql.nprint(path)
        ql.os.file_des[bind_fd].bind(path)

    # need a proper fix, for now ipv4 comes first
    elif sin_family == 2 and ql.bindtolocalhost == True:
        ql.os.file_des[bind_fd].bind(('127.0.0.1', port))
        host = "127.0.0.1"

    # IPv4 should comes first
    elif ql.ipv6 == True and sin_family == 10 and ql.bindtolocalhost == True:
        ql.os.file_des[bind_fd].bind(('::1', port))
        host = "::1"

    elif ql.bindtolocalhost == False:
        ql.os.file_des[bind_fd].bind((host, port))

    else:
        regreturn = -1

    if ql.shellcoder:
        regreturn = 0

    if sin_family == 1:
        ql.nprint("bind(%d, %s, %d) = %d" % (bind_fd, path, bind_addrlen, regreturn))
    else:
        ql.nprint("bind(%d,%s:%d,%d) = %d" % (bind_fd, host, port, bind_addrlen,regreturn))
        ql.dprint (0, "[+] syscall bind host: %s and port: %i sin_family: %i" % (ql_bin_to_ip(host), port, sin_family))

    ql.os.definesyscall_return(regreturn)


def ql_syscall_listen(ql, listen_sockfd, listen_backlog, *args, **kw):
    if listen_sockfd < 256 and ql.os.file_des[listen_sockfd] != 0:
        try:
            ql.os.file_des[listen_sockfd].listen(listen_backlog)
            regreturn = 0
        except:
            if ql.output == QL_OUTPUT.DEBUG:
                raise
            regreturn = -1
    else:
        regreturn = -1
    ql.nprint("listen(%d, %d) = %d" % (listen_sockfd, listen_backlog, regreturn))
    ql.os.definesyscall_return(regreturn)


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
        conn, address = ql.os.file_des[accept_sockfd].accept()
        idx = -1
        for i in range(256):
            if ql.os.file_des[i] == 0:
                idx = i
                break
        if idx == -1:
            regreturn = -1
        else:
            ql.os.file_des[idx] = conn
            regreturn = idx

        if ql.shellcoder == None and accept_addr !=0 and accept_addrlen != 0:
            tmp_buf = ql.pack16(conn.family)
            tmp_buf += ql.pack16(address[1])
            tmp_buf += inet_addr(address[0])
            tmp_buf += b'\x00' * 8
            ql.mem.write(accept_addr, tmp_buf)
            ql.mem.write(accept_addrlen, ql.pack32(16))
    except:
        if ql.output in (QL_OUTPUT.DEBUG, QL_OUTPUT.DUMP):
            raise
        regreturn = -1
    ql.nprint("accept(%d, %x, %x) = %d" %(accept_sockfd, accept_addr, accept_addrlen, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_recv(ql, recv_sockfd, recv_buf, recv_len, recv_flags, *args, **kw):
    if recv_sockfd < 256 and ql.os.file_des[recv_sockfd] != 0:
        tmp_buf = ql.os.file_des[recv_sockfd].recv(recv_len, recv_flags)
        if tmp_buf:
            ql.dprint(D_CTNT, "[+] recv() CONTENT:")
            ql.dprint(D_CTNT, "%s" % tmp_buf)
        ql.mem.write(recv_buf, tmp_buf)
        regreturn = len(tmp_buf)
    else:
        regreturn = -1
    ql.nprint("recv(%d, %x, %d, %x) = %d" % (recv_sockfd, recv_buf, recv_len, recv_flags, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_send(ql, send_sockfd, send_buf, send_len, send_flags, *args, **kw):
    regreturn = 0
    if send_sockfd < 256 and ql.os.file_des[send_sockfd] != 0:
        try:
            ql.dprint(D_CTNT, "[+] debug send() start")
            tmp_buf = ql.mem.read(send_buf, send_len)
            ql.dprint(D_CTNT, str(ql.os.file_des[send_sockfd]))
            ql.dprint(D_CTNT, "[+] fd is " + str(send_sockfd))
            ql.dprint(D_CTNT, "[+] send() CONTENT:")
            ql.dprint(D_CTNT, "%s" % str(tmp_buf))
            ql.dprint(D_CTNT, "[+] send() flag is " + str(send_flags))
            ql.dprint(D_CTNT, "[+] send() len is " + str(send_len))
            ql.os.file_des[send_sockfd].send(bytes(tmp_buf), send_flags)
            ql.dprint(D_CTNT, str(ql.os.file_des[send_sockfd]))
            regreturn = send_len
            ql.dprint(D_CTNT, "[+] debug send end")
        except:
            ql.nprint(sys.exc_info()[0])
            if ql.output in (QL_OUTPUT.DEBUG, QL_OUTPUT.DUMP):
                raise
    else:
        regreturn = -1
    ql.nprint("send(%d, %x, %d, %x) = %d" % (send_sockfd, send_buf, send_len, send_flags, regreturn))
    ql.os.definesyscall_return(regreturn)
