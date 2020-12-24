#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import struct, ipaddress, logging

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
        if ql.os.fd[i] == 0:
            idx = i
            break
    try:
        if idx == -1:
            regreturn = -1
        else:
            if ql.output == QL_OUTPUT.DEBUG: # set REUSEADDR options under debug mode
                ql.os.fd[idx] = ql_socket.open(socket_domain, socket_type, socket_protocol, (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1))
            else:
                ql.os.fd[idx] = ql_socket.open(socket_domain, socket_type, socket_protocol)

            regreturn = (idx)
    except:
        regreturn = -1

    logging.info("socket(%d, %d, %d) = %d" % (socket_domain, socket_type, socket_protocol, regreturn))

    socket_type = socket_type_mapping(socket_type, ql.archtype)
    socket_domain = socket_domain_mapping(socket_domain, ql.archtype)
    logging.debug("[+] socket(%s, %s, %s) = %d" % (socket_domain, socket_type, socket_protocol, regreturn))

    ql.os.definesyscall_return(regreturn)


def ql_syscall_connect(ql, connect_sockfd, connect_addr, connect_addrlen, *args, **kw):
    AF_UNIX = 1
    AF_INET = 2
    sock_addr = ql.mem.read(connect_addr, connect_addrlen)
    family = ql.unpack16(sock_addr[ : 2])
    s = ql.os.fd[connect_sockfd]
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
        logging.info("connect(%s) = %d" % (sun_path, regreturn))
    elif s.family == AF_INET:
        logging.info("connect(%s, %d) = %d" % (ip, port, regreturn))
    else:
        logging.info("connect() = %d" % (regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_setsockopt(ql, *args, **kw):
    regreturn = 0
    logging.info("setsockopt() = %d" % (regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_shutdown(ql, shutdown_fd, shutdown_how, *args, **kw):
    if shutdown_fd >=0 and shutdown_fd < 256 and ql.os.fd[shutdown_fd] != 0:
        try:
            ql.os.fd[shutdown_fd].shutdown(shutdown_how)
            regreturn = 0
        except:
            regreturn = -1
    logging.info("shutdown(%d, %d) = %d" % (shutdown_fd, shutdown_how, regreturn))            
    ql.os.definesyscall_return(regreturn)


def ql_syscall_bind(ql, bind_fd, bind_addr, bind_addrlen,  *args, **kw):
    regreturn = 0

    if ql.archtype == QL_ARCH.X8664:
        data = ql.mem.read(bind_addr, 8)
    else:
        data = ql.mem.read(bind_addr, bind_addrlen)

    sin_family = ql.unpack16(data[:2]) or ql.os.fd[bind_fd].family
    port, host = struct.unpack(">HI", data[2:8])
    host = ql_bin_to_ip(host)

    if ql.root == False and port <= 1024:
        port = port + 8000

    if sin_family == 1:
        path = data[2 : ].split(b'\x00')[0]
        path = ql.os.transform_to_real_path(path.decode())
        logging.info(path)
        ql.os.fd[bind_fd].bind(path)

    # need a proper fix, for now ipv4 comes first
    elif sin_family == 2 and ql.os.bindtolocalhost == True:
        ql.os.fd[bind_fd].bind(('127.0.0.1', port))
        host = "127.0.0.1"

    # IPv4 should comes first
    elif ql.os.ipv6 == True and sin_family == 10 and ql.os.bindtolocalhost == True:
        ql.os.fd[bind_fd].bind(('::1', port))
        host = "::1"

    elif ql.os.bindtolocalhost == False:
        ql.os.fd[bind_fd].bind((host, port))

    else:
        regreturn = -1

    if ql.shellcoder:
        regreturn = 0

    if sin_family == 1:
        logging.info("bind(%d, %s, %d) = %d" % (bind_fd, path, bind_addrlen, regreturn))
    else:
        logging.info("bind(%d,%s:%d,%d) = %d" % (bind_fd, host, port, bind_addrlen,regreturn))
        logging.debug("[+] syscall bind host: %s and port: %i sin_family: %i" % (ql_bin_to_ip(host), port, sin_family))

    ql.os.definesyscall_return(regreturn)


def ql_syscall_getsockname(ql, sockfd, addr, addrlenptr, *args, **kw):
    if sockfd < 256 and ql.os.fd[sockfd] != 0:
        host, port = ql.os.fd[sockfd].getsockname()
        data = struct.pack("<h", int(ql.os.fd[sockfd].family))
        data += struct.pack(">H", port)
        data += ipaddress.ip_address(host).packed
        addrlen = ql.mem.read(addrlenptr, 4)
        addrlen = ql.unpack32(addrlen)
        data = data[:addrlen]
        ql.mem.write(addr, data)
        regreturn = 0
    else:
        regreturn = -1

    logging.info("getsockname(%d, 0x%x, 0x%x) = %d" % (sockfd, addr, addrlenptr, regreturn))
    ql.os.definesyscall_return(regreturn)  


def ql_syscall_getpeername(ql, sockfd, addr, addrlenptr, *args, **kw):
    if sockfd < 256 and ql.os.fd[sockfd] != 0:
        host, port = ql.os.fd[sockfd].getpeername()
        data = struct.pack("<h", int(ql.os.fd[sockfd].family))
        data += struct.pack(">H", port)
        data += ipaddress.ip_address(host).packed
        addrlen = ql.mem.read(addrlenptr, 4)
        addrlen = ql.unpack32(addrlen)
        data = data[:addrlen]
        ql.mem.write(addr, data)
        regreturn = 0
    else:
        regreturn = -1

    logging.info("getpeername(%d, 0x%x, 0x%x) = %d" % (sockfd, addr, addrlenptr, regreturn))
    ql.os.definesyscall_return(regreturn)  


def ql_syscall_listen(ql, listen_sockfd, listen_backlog, *args, **kw):
    if listen_sockfd < 256 and ql.os.fd[listen_sockfd] != 0:
        try:
            ql.os.fd[listen_sockfd].listen(listen_backlog)
            regreturn = 0
        except:
            if ql.output == QL_OUTPUT.DEBUG:
                raise
            regreturn = -1
    else:
        regreturn = -1

    logging.info("listen(%d, %d) = %d" % (listen_sockfd, listen_backlog, regreturn))
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
        conn, address = ql.os.fd[accept_sockfd].accept()
        if conn == None:
            ql.os.definesyscall_return(-1)
            return

        idx = -1
        for i in range(256):
            if ql.os.fd[i] == 0:
                idx = i
                break
        if idx == -1:
            regreturn = -1
        else:
            ql.os.fd[idx] = conn
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

    logging.info("accept(%d, %x, %x) = %d" %(accept_sockfd, accept_addr, accept_addrlen, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_recv(ql, recv_sockfd, recv_buf, recv_len, recv_flags, *args, **kw):
    if recv_sockfd < 256 and ql.os.fd[recv_sockfd] != 0:
        tmp_buf = ql.os.fd[recv_sockfd].recv(recv_len, recv_flags)
        if tmp_buf:
            logging.debug("[+] recv() CONTENT:")
            logging.debug("%s" % tmp_buf)
        ql.mem.write(recv_buf, tmp_buf)
        regreturn = len(tmp_buf)
    else:
        regreturn = -1

    logging.info("recv(%d, %x, %d, %x) = %d" % (recv_sockfd, recv_buf, recv_len, recv_flags, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_send(ql, send_sockfd, send_buf, send_len, send_flags, *args, **kw):
    regreturn = 0
    if send_sockfd < 256 and ql.os.fd[send_sockfd] != 0:
        try:
            logging.debug("[+] debug send() start")
            tmp_buf = ql.mem.read(send_buf, send_len)  
            logging.debug("[+] fd is " + str(send_sockfd))
            logging.debug("[+] send() CONTENT:")
            logging.debug("%s" % str(tmp_buf))
            logging.debug("[+] send() flag is " + str(send_flags))
            logging.debug("[+] send() len is " + str(send_len))
            regreturn = ql.os.fd[send_sockfd].send(bytes(tmp_buf), send_flags)
            logging.debug("[+] debug send end")
        except:
            logging.info(sys.exc_info()[0])
            if ql.output in (QL_OUTPUT.DEBUG, QL_OUTPUT.DUMP):
                raise
    else:
        regreturn = -1

    logging.info("send(%d, %x, %d, %x) = %d" % (send_sockfd, send_buf, send_len, send_flags, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_recvfrom(ql, recvfrom_sockfd, recvfrom_buf, recvfrom_len, recvfrom_flags, recvfrom_addr, recvfrom_addrlen, *args, **kw):
    # For x8664, recvfrom() is called finally when calling recv() in TCP communications
    SOCK_STREAM = 1
    if ql.os.fd[recvfrom_sockfd].socktype == SOCK_STREAM:
        ql_syscall_recv(ql, recvfrom_sockfd, recvfrom_buf, recvfrom_len, recvfrom_flags, *args, **kw)
    else:
        if recvfrom_sockfd < 256 and ql.os.fd[recvfrom_sockfd] != 0:
            tmp_buf, tmp_addr = ql.os.fd[recvfrom_sockfd].recvfrom(recvfrom_len, recvfrom_flags)
            if tmp_buf:
                logging.debug("[+] recvfrom() CONTENT:")
                logging.debug("%s" % tmp_buf)

            sin_family = int(ql.os.fd[recvfrom_sockfd].family)
            data = struct.pack("<h", sin_family)
            if sin_family == 1:
                logging.debug("[+] recvfrom() path is " + tmp_addr)
                data += tmp_addr.encode()
            else:
                logging.debug("[+] recvfrom() addr is %s:%d" % (tmp_addr[0], tmp_addr[1]))
                data += struct.pack(">H", tmp_addr[1])
                data += ipaddress.ip_address(tmp_addr[0]).packed
                addrlen = ql.unpack(ql.mem.read(recvfrom_addrlen, ql.pointersize))
                data = data[:addrlen]
            ql.mem.write(recvfrom_addr, data)

            ql.mem.write(recvfrom_buf, tmp_buf)
            regreturn = len(tmp_buf)
        else:
            regreturn = -1

        logging.info("recvfrom(%d, %#x, %d, %#x, %#x, %#x) = %d" % (recvfrom_sockfd, recvfrom_buf, recvfrom_len, recvfrom_flags, recvfrom_addr, recvfrom_addrlen, regreturn))
        ql.os.definesyscall_return(regreturn)


def ql_syscall_sendto(ql, sendto_sockfd, sendto_buf, sendto_len, sendto_flags, sendto_addr, sendto_addrlen, *args, **kw):
    # For x8664, sendto() is called finally when calling send() in TCP communications
    SOCK_STREAM = 1
    if ql.os.fd[sendto_sockfd].socktype == SOCK_STREAM:
        ql_syscall_send(ql, sendto_sockfd, sendto_buf, sendto_len, sendto_flags, *args, **kw)
    else:
        regreturn = 0
        if sendto_sockfd < 256 and ql.os.fd[sendto_sockfd] != 0:
            try:
                logging.debug("[+] debug sendto() start")
                tmp_buf = ql.mem.read(sendto_buf, sendto_len)

                if ql.archtype== QL_ARCH.X8664:
                    data = ql.mem.read(sendto_addr, 8)
                else:
                    data = ql.mem.read(sendto_addr, sendto_addrlen)

                sin_family, = struct.unpack("<h", data[:2])
                port, host = struct.unpack(">HI", data[2:8])
                host = ql_bin_to_ip(host)

                if sin_family == 1:
                    path = data[2 : ].split(b'\x00')[0]
                    path = ql.os.transform_to_real_path(path.decode())

                logging.debug("[+] fd is " + str(sendto_sockfd))
                logging.debug("[+] sendto() CONTENT:")
                logging.debug("%s" % tmp_buf)
                logging.debug("[+] sendto() flag is " + str(sendto_flags))
                logging.debug("[+] sendto() len is " + str(sendto_len))
                if sin_family == 1:
                    logging.debug("[+] sendto() path is " + str(path))
                    regreturn = ql.os.fd[sendto_sockfd].sendto(bytes(tmp_buf), sendto_flags, path)
                else:
                    logging.debug("[+] sendto() addr is %s:%d" % (host, port))
                    regreturn = ql.os.fd[sendto_sockfd].sendto(bytes(tmp_buf), sendto_flags, (host, port))
                logging.debug("[+] debug sendto end")
            except:
                logging.info(sys.exc_info()[0])
                if ql.output in (QL_OUTPUT.DEBUG, QL_OUTPUT.DUMP):
                    raise
        else:
            regreturn = -1

        logging.info("sendto(%d, %#x, %d, %#x, %#x, %#x) = %d" % (sendto_sockfd, sendto_buf, sendto_len, sendto_flags, sendto_addr, sendto_addrlen, regreturn))
        ql.os.definesyscall_return(regreturn)
