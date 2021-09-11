#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
import ipaddress
import sys
import socket
import struct

from unicorn.unicorn import UcError

from qiling import Qiling
from qiling.const import QL_ARCH, QL_VERBOSE
from qiling.os.posix.const_mapping import socket_type_mapping, socket_level_mapping, socket_domain_mapping, socket_ip_option_mapping, socket_option_mapping
from qiling.os.posix.const import *
from qiling.os.posix.filestruct import ql_socket

class msghdr(ctypes.Structure):
    _fields_ = [
        ('msg_name'      , ctypes.c_uint64),
        ('msg_namelen'   , ctypes.c_int32 ),
        ('msg_iov'       , ctypes.c_uint64),
        ('msg_iovlen'    , ctypes.c_int32 ),
        ('msg_control'   , ctypes.c_uint64),
        ('msg_controllen', ctypes.c_int32 ),
        ('msg_flags'     , ctypes.c_int32 )
    ]

    _pack_ = 8

    @classmethod
    def load(cls, ql: Qiling, addr: int):
        data = ql.mem.read(addr, ctypes.sizeof(msghdr))
        return msghdr.from_buffer(data)

class cmsghdr(ctypes.Structure):
    _fields_ = [
        ('cmsg_len'  , ctypes.c_int32),
        ('cmsg_level', ctypes.c_int32),
        ('cmsg_type' , ctypes.c_int32),
    ]

    _pack_ = 8

    @classmethod
    def load(cls, ql: Qiling, addr: int):
        data = ql.mem.read(addr, ctypes.sizeof(cmsghdr))
        return cmsghdr.from_buffer(data)

class iovec(ctypes.Structure):
    _fields_ = [
        ('iov_base', ctypes.c_uint64),
        ('iov_len' , ctypes.c_uint64),
    ]

    _pack_ = 8

    @classmethod
    def load(cls, ql: Qiling, addr: int):
        data = ql.mem.read(addr, ctypes.sizeof(iovec))
        return iovec.from_buffer(data)


def ql_bin_to_ip(ip):
    return ipaddress.ip_address(ip).compressed


def ql_syscall_socket(ql: Qiling, socket_domain, socket_type, socket_protocol):
    idx = -1
    for i in range(NR_OPEN):
        if ql.os.fd[i] == 0:
            idx = i
            break
    try:
        if idx == -1:
            regreturn = -1
        else:
            # ql_socket.open should use host platform based socket_type.
            try:
                emu_socket_value = socket_type
                emu_socket_type = socket_type_mapping(socket_type, ql.archtype)
                socket_type = getattr(socket, emu_socket_type)
                ql.log.debug("Convert emu_socket_type {}:{} to host platform based socket_type {}:{}".format(
                    emu_socket_type, emu_socket_value, emu_socket_type, socket_type))

            except AttributeError:
                ql.log.error("Can't convert emu_socket_type {}:{} to host platform based socket_type".format(
                    emu_socket_type, emu_socket_value))
                raise

            except Exception:
                ql.log.error("Can't convert emu_socket_type {} to host platform based socket_type".format(
                    emu_socket_value))
                raise

            if ql.verbose >= QL_VERBOSE.DEBUG:  # set REUSEADDR options under debug mode
                ql.os.fd[idx] = ql_socket.open(socket_domain, socket_type, socket_protocol, (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1))
            else:
                ql.os.fd[idx] = ql_socket.open(socket_domain, socket_type, socket_protocol)

            regreturn = (idx)

    except Exception:
        ql.log.exception("")
        regreturn = -1

    socket_type = socket_type_mapping(socket_type, ql.archtype)
    socket_domain = socket_domain_mapping(socket_domain, ql.archtype)
    ql.log.debug("socket(%s, %s, %s) = %d" % (socket_domain, socket_type, socket_protocol, regreturn))

    return regreturn


def ql_syscall_connect(ql: Qiling, connect_sockfd, connect_addr, connect_addrlen):
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
                sun_path = ql.os.path.transform_to_real_path(sun_path.decode())
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
        ql.log.debug("connect(%s) = %d" % (sun_path, regreturn))
    elif s.family == AF_INET:
        ql.log.debug("connect(%s, %d) = %d" % (ip, port, regreturn))
    else:
        ql.log.debug("connect() = %d" % (regreturn))
    return regreturn


def ql_syscall_getsockopt(ql: Qiling, sockfd, level, optname, optval_addr, optlen_addr):
    if not (0 <= sockfd < NR_OPEN) or ql.os.fd[sockfd] == 0:
        return -EBADF

    try:
        optlen = min(ql.unpack32s(ql.mem.read(optlen_addr, 4)), 1024)
        if optlen < 0:
            return -EINVAL

        try:
            emu_level = level
            emu_level_name = socket_level_mapping(emu_level, ql.archtype)
            level = getattr(socket, emu_level_name)
            ql.log.debug("Convert emu_level {}:{} to host platform based level {}:{}".format(
                emu_level_name, emu_level, emu_level_name, level))

        except AttributeError:
            ql.log.error("Can't convert emu_level {}:{} to host platform based emu_level".format(
                emu_level_name, emu_level))
            raise

        except Exception:
            ql.log.error("Can't convert emu_level {} to host platform based level".format(emu_level))
            raise

        try:
            emu_opt = optname

            emu_level_name = socket_level_mapping(emu_level, ql.archtype)
            # emu_opt_name is based on level
            if emu_level_name == "IPPROTO_IP":
                emu_opt_name = socket_ip_option_mapping(emu_opt, ql.archtype)
            else:
                emu_opt_name = socket_option_mapping(emu_opt, ql.archtype)

            # Fix for mips
            if ql.archtype == QL_ARCH.MIPS:
                if emu_opt_name.endswith("_NEW") or emu_opt_name.endswith("_OLD"):
                    emu_opt_name = emu_opt_name[:-4]

            optname = getattr(socket, emu_opt_name)
            ql.log.debug("Convert emu_optname {}:{} to host platform based optname {}:{}".format(
                emu_opt_name, emu_opt, emu_opt_name, optname))

        except AttributeError:
            ql.log.error("Can't convert emu_optname {}:{} to host platform based emu_optname".format(
                emu_opt_name, emu_opt))
            raise

        except Exception:
            ql.log.error("Can't convert emu_optname {} to host platform based optname".format(emu_opt))
            raise

        optval = ql.os.fd[sockfd].getsockopt(level, optname, optlen)
        ql.mem.write(optval_addr, optval)
    except UcError:
        return -EFAULT

    return 0


def ql_syscall_setsockopt(ql: Qiling, sockfd, level, optname, optval_addr, optlen):
    if not (0 <= sockfd < NR_OPEN) or\
            ql.os.fd[sockfd] == 0:
        return -EBADF

    regreturn = 0
    if optval_addr == 0:
        ql.os.fd[sockfd].setsockopt(level, optname, None, optlen)
    else:
        try:
            try:
                emu_level = level
                emu_level_name = socket_level_mapping(emu_level, ql.archtype)
                level = getattr(socket, emu_level_name)
                ql.log.debug("Convert emu_level {}:{} to host platform based level {}:{}".format(
                    emu_level_name, emu_level, emu_level_name, level))

            except AttributeError:
                ql.log.error("Can't convert emu_level {}:{} to host platform based emu_level".format(
                    emu_level_name, emu_level))
                raise

            except Exception:
                ql.log.error("Can't convert emu_level {} to host platform based level".format(emu_level))
                raise

            try:
                emu_opt = optname

                emu_level_name = socket_level_mapping(emu_level, ql.archtype)
                # emu_opt_name is based on level
                if emu_level_name == "IPPROTO_IP":
                    emu_opt_name = socket_ip_option_mapping(emu_opt, ql.archtype)
                else:
                    emu_opt_name = socket_option_mapping(emu_opt, ql.archtype)

                # Fix for mips
                if ql.archtype == QL_ARCH.MIPS:
                    if emu_opt_name.endswith("_NEW") or emu_opt_name.endswith("_OLD"):
                        emu_opt_name = emu_opt_name[:-4]

                optname = getattr(socket, emu_opt_name)
                ql.log.debug("Convert emu_optname {}:{} to host platform based optname {}:{}".format(
                    emu_opt_name, emu_opt, emu_opt_name, optname))

            except AttributeError:
                ql.log.error("Can't convert emu_optname {}:{} to host platform based emu_optname".format(
                    emu_opt_name, emu_opt))
                raise

            except Exception:
                ql.log.error("Can't convert emu_optname {} to host platform based optname".format(emu_opt))
                raise

            optval = ql.mem.read(optval_addr, optlen)
            ql.os.fd[sockfd].setsockopt(level, optname, optval, None)

        except UcError:
            regreturn = -EFAULT

        except:
            regreturn = -1

    return regreturn


def ql_syscall_shutdown(ql: Qiling, shutdown_fd, shutdown_how):
    if 0 <= shutdown_fd < NR_OPEN and ql.os.fd[shutdown_fd] != 0:
        try:
            ql.os.fd[shutdown_fd].shutdown(shutdown_how)
        except:
            regreturn = -1
        else:
            regreturn = 0

    return regreturn


def ql_syscall_bind(ql: Qiling, bind_fd, bind_addr, bind_addrlen):
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
        path = ql.os.path.transform_to_real_path(path.decode())
        ql.log.info(path)
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

    if ql.code:
        regreturn = 0

    if sin_family == 1:
        ql.log.debug("bind(%d, %s, %d) = %d" % (bind_fd, path, bind_addrlen, regreturn))
    else:
        ql.log.debug("bind(%d,%s:%d,%d) = %d" % (bind_fd, host, port, bind_addrlen,regreturn))
        ql.log.debug("syscall bind host: %s and port: %i sin_family: %i" % (ql_bin_to_ip(host), port, sin_family))

    return regreturn


def ql_syscall_getsockname(ql: Qiling, sockfd, addr, addrlenptr):
    if 0 <= sockfd < NR_OPEN and ql.os.fd[sockfd] != 0:
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

    ql.log.debug("getsockname(%d, 0x%x, 0x%x) = %d" % (sockfd, addr, addrlenptr, regreturn))
    return regreturn


def ql_syscall_getpeername(ql: Qiling, sockfd, addr, addrlenptr):
    if 0 <= sockfd < NR_OPEN and ql.os.fd[sockfd] != 0:
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

    ql.log.debug("getpeername(%d, 0x%x, 0x%x) = %d" % (sockfd, addr, addrlenptr, regreturn))
    return regreturn


def ql_syscall_listen(ql: Qiling, listen_sockfd, listen_backlog):
    if 0 <= listen_sockfd < NR_OPEN and ql.os.fd[listen_sockfd] != 0:
        try:
            ql.os.fd[listen_sockfd].listen(listen_backlog)
            regreturn = 0
        except:
            if ql.verbose >= QL_VERBOSE.DEBUG:
                raise
            regreturn = -1
    else:
        regreturn = -1
    return regreturn


def ql_syscall_accept(ql: Qiling, accept_sockfd, accept_addr, accept_addrlen):
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
            return -1

        idx = -1
        for i in range(NR_OPEN):
            if ql.os.fd[i] == 0:
                idx = i
                break
        if idx == -1:
            regreturn = -1
        else:
            ql.os.fd[idx] = conn
            regreturn = idx

        if ql.code == None and accept_addr !=0 and accept_addrlen != 0:
            tmp_buf = ql.pack16(conn.family)
            tmp_buf += ql.pack16(address[1])
            tmp_buf += inet_addr(address[0])
            tmp_buf += b'\x00' * 8
            ql.mem.write(accept_addr, tmp_buf)
            ql.mem.write(accept_addrlen, ql.pack32(16))
    except:
        if ql.verbose >= QL_VERBOSE.DEBUG:
            raise
        regreturn = -1

    return regreturn


def ql_syscall_recv(ql: Qiling, recv_sockfd, recv_buf, recv_len, recv_flags):
    if 0 <= recv_sockfd < NR_OPEN and ql.os.fd[recv_sockfd] != 0:
        tmp_buf = ql.os.fd[recv_sockfd].recv(recv_len, recv_flags)
        if tmp_buf:
            ql.log.debug("recv() CONTENT:")
            ql.log.debug("%s" % tmp_buf)
        ql.mem.write(recv_buf, tmp_buf)
        regreturn = len(tmp_buf)
    else:
        regreturn = -1
    return regreturn


def ql_syscall_send(ql: Qiling, send_sockfd, send_buf, send_len, send_flags):
    regreturn = 0
    if 0 <= send_sockfd < NR_OPEN and ql.os.fd[send_sockfd] != 0:
        try:
            ql.log.debug("debug send() start")
            tmp_buf = ql.mem.read(send_buf, send_len)
            ql.log.debug("fd is " + str(send_sockfd))
            ql.log.debug("send() CONTENT:")
            ql.log.debug("%s" % str(tmp_buf))
            ql.log.debug("send() flag is " + str(send_flags))
            ql.log.debug("send() len is " + str(send_len))
            regreturn = ql.os.fd[send_sockfd].send(bytes(tmp_buf), send_flags)
            ql.log.debug("debug send end")
        except:
            ql.log.info(sys.exc_info()[0])
            if ql.verbose >= QL_VERBOSE.DEBUG:
                raise
    else:
        regreturn = -1
    return regreturn


def ql_syscall_recvmsg(ql: Qiling, sockfd, msg_addr, flags):
    regreturn = 0
    if  0 <= sockfd < NR_OPEN and ql.os.fd[sockfd] != 0:
        msg = msghdr.load(ql, msg_addr)

        try:
            data, ancdata, mflags, addr = ql.os.fd[sockfd].recvmsg(msg.msg_namelen, msg.msg_controllen, flags)

            # TODO: handle the addr

            iovec_addr  = msg.msg_iov
            has_written = 0
            for i in range(msg.msg_iovlen):
                vec = iovec.load(ql, iovec_addr)
                size = min(vec.iov_len, len(data) - has_written)
                ql.mem.write(
                    vec.iov_base,
                    data[has_written: has_written + size]
                )
                iovec_addr += ctypes.sizeof(iovec)

            cmsg_addr = msg.msg_control
            for cmsg_level, cmsg_type, cmsg_data in ancdata:
                cmsg = cmsghdr.load(ql, cmsg_addr)
                cmsg.cmsg_len = len(cmsg_data)
                cmsg.cmsg_level = cmsg_level
                cmsg.cmsg_type = cmsg_type
                cmsg_data_addr = cmsg_addr + ctypes.sizeof(cmsghdr)

                ql.mem.write(cmsg_data_addr, cmsg_data)
                ql.mem.write(cmsg_addr, bytes(cmsg))

                cmsg_addr += cmsg.cmsg_len

            msg.msg_flags = mflags
            ql.mem.write(msg_addr, bytes(msg))

            regreturn = len(data)
        except OSError as e:
            regreturn = -e.errno
    else:
        regreturn = -EBADF

    return regreturn

def ql_syscall_recvfrom(ql: Qiling, recvfrom_sockfd, recvfrom_buf, recvfrom_len, recvfrom_flags, recvfrom_addr, recvfrom_addrlen):
    # For x8664, recvfrom() is called finally when calling recv() in TCP communications
    SOCK_STREAM = 1
    if ql.os.fd[recvfrom_sockfd].socktype == SOCK_STREAM:
        return ql_syscall_recv(ql, recvfrom_sockfd, recvfrom_buf, recvfrom_len, recvfrom_flags)
    else:
        if 0 <= recvfrom_sockfd < NR_OPEN and ql.os.fd[recvfrom_sockfd] != 0:
            tmp_buf, tmp_addr = ql.os.fd[recvfrom_sockfd].recvfrom(recvfrom_len, recvfrom_flags)
            if tmp_buf:
                ql.log.debug("recvfrom() CONTENT:")
                ql.log.debug("%s" % tmp_buf)

            sin_family = int(ql.os.fd[recvfrom_sockfd].family)
            data = struct.pack("<h", sin_family)
            if sin_family == 1:
                ql.log.debug("recvfrom() path is " + tmp_addr)
                data += tmp_addr.encode()
            else:
                ql.log.debug("recvfrom() addr is %s:%d" % (tmp_addr[0], tmp_addr[1]))
                data += struct.pack(">H", tmp_addr[1])
                data += ipaddress.ip_address(tmp_addr[0]).packed
                addrlen = ql.unpack(ql.mem.read(recvfrom_addrlen, ql.pointersize))
                data = data[:addrlen]
            ql.mem.write(recvfrom_addr, data)

            ql.mem.write(recvfrom_buf, tmp_buf)
            regreturn = len(tmp_buf)
        else:
            regreturn = -1

        return regreturn


def ql_syscall_sendto(ql: Qiling, sendto_sockfd, sendto_buf, sendto_len, sendto_flags, sendto_addr, sendto_addrlen):
    # For x8664, sendto() is called finally when calling send() in TCP communications
    SOCK_STREAM = 1
    if ql.os.fd[sendto_sockfd].socktype == SOCK_STREAM:
        return ql_syscall_send(ql, sendto_sockfd, sendto_buf, sendto_len, sendto_flags)
    else:
        regreturn = 0
        if 0 <= sendto_sockfd < NR_OPEN and ql.os.fd[sendto_sockfd] != 0:
            try:
                ql.log.debug("debug sendto() start")
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
                    path = ql.os.path.transform_to_real_path(path.decode())

                ql.log.debug("fd is " + str(sendto_sockfd))
                ql.log.debug("sendto() CONTENT:")
                ql.log.debug("%s" % tmp_buf)
                ql.log.debug("sendto() flag is " + str(sendto_flags))
                ql.log.debug("sendto() len is " + str(sendto_len))
                if sin_family == 1:
                    ql.log.debug("sendto() path is " + str(path))
                    regreturn = ql.os.fd[sendto_sockfd].sendto(bytes(tmp_buf), sendto_flags, path)
                else:
                    ql.log.debug("sendto() addr is %s:%d" % (host, port))
                    regreturn = ql.os.fd[sendto_sockfd].sendto(bytes(tmp_buf), sendto_flags, (host, port))
                ql.log.debug("debug sendto end")
            except:
                ql.log.debug(sys.exc_info()[0])
                if ql.verbose >= QL_VERBOSE.DEBUG:
                    raise
        else:
            regreturn = -1

        return regreturn
