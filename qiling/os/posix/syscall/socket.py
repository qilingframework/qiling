#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
import ipaddress
import sys
import socket
import struct
from typing import Tuple

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


def ql_unix_socket_path(ql: Qiling, sun_path: bytearray) -> Tuple[str, str]:
    if sun_path[0] == 0:
        # Abstract Unix namespace
        # TODO: isolate from host namespace
        # TODO: Windows
        ql.log.warning(f'Beware! Usage of hosts abstract socket namespace {bytes(sun_path)}')

        return (sun_path.decode(), '')

    vpath = sun_path.split(b'\0', maxsplit=1)[0].decode()
    hpath = ql.os.path.virtual_to_host_path(vpath)

    return (hpath, vpath)


def ql_syscall_socket(ql: Qiling, socket_domain, socket_type, socket_protocol):
    idx = next((i for i in range(NR_OPEN) if ql.os.fd[i] is None), -1)

    if idx != -1:
        emu_socket_value = socket_type

        # ql_socket.open should use host platform based socket_type.
        try:
            emu_socket_type = socket_type_mapping(socket_type, ql.arch.type, ql.os.type)
        except KeyError:
            ql.log.error(f'Cannot convert emu_socket_type {emu_socket_value} to host platform based socket_type')
            raise

        try:
            socket_type = getattr(socket, emu_socket_type)
        except AttributeError:
            ql.log.error(f'Cannot convert emu_socket_type {emu_socket_type}:{emu_socket_value} to host platform based socket_type')
            raise

        ql.log.debug(f'Convert emu_socket_type {emu_socket_type}:{emu_socket_value} to host platform based socket_type {emu_socket_type}:{socket_type}')

        try:
            sock = ql_socket.open(socket_domain, socket_type, socket_protocol)

            # set REUSEADDR options under debug mode
            if ql.verbose >= QL_VERBOSE.DEBUG:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            ql.os.fd[idx] = sock

        # May raise error: Protocol not supported
        except OSError as e:
            ql.log.debug(f'{e}: {socket_domain=}, {socket_type=}, {socket_protocol=}')
            idx = -1

    socket_type = socket_type_mapping(socket_type, ql.arch.type, ql.os.type)
    socket_domain = socket_domain_mapping(socket_domain, ql.arch.type, ql.os.type)
    ql.log.debug("socket(%s, %s, %s) = %d" % (socket_domain, socket_type, socket_protocol, idx))

    return idx


def ql_syscall_connect(ql: Qiling, sockfd: int, addr: int, addrlen: int):
    AF_UNIX = 1
    AF_INET = 2

    sock_addr = ql.mem.read(addr, addrlen)
    family = ql.unpack16(sock_addr[:2])

    sock = ql.os.fd[sockfd]
    assert isinstance(sock, ql_socket)

    dest = None

    if sock.family != family:
        return -1

    if sock.family == AF_UNIX:
        hpath, vpath = ql_unix_socket_path(ql, sock_addr[2:])

        ql.log.debug(f'connecting to "{vpath}"')
        dest = hpath

    elif sock.family == AF_INET:
        port, host = struct.unpack(">HI", sock_addr[2:8])
        ip = ql_bin_to_ip(host)

        ql.log.debug(f'connecting to {ip}:{port}')
        dest = (ip, port)

    else:
        return -1

    try:
        sock.connect(dest)
    except:
        regreturn = -1
    else:
        regreturn = 0

    return regreturn


def ql_syscall_getsockopt(ql: Qiling, sockfd, level, optname, optval_addr, optlen_addr):
    if sockfd not in range(NR_OPEN) or ql.os.fd[sockfd] is None:
        return -EBADF

    try:
        optlen = min(ql.unpack32s(ql.mem.read(optlen_addr, 4)), 1024)

        if optlen < 0:
            return -EINVAL

        emu_level = level

        try:
            emu_level_name = socket_level_mapping(emu_level, ql.arch.type, ql.os.type)
        except KeyError:
            ql.log.error(f"Can't convert emu_level {emu_level} to host platform based level")
            raise

        try:
            level = getattr(socket, emu_level_name)
        except AttributeError:
            ql.log.error(f"Can't convert emu_level {emu_level_name}:{emu_level} to host platform based emu_level")
            raise

        ql.log.debug(f"Convert emu_level {emu_level_name}:{emu_level} to host platform based level {emu_level_name}:{level}")

        emu_opt = optname

        try:
            emu_level_name = socket_level_mapping(emu_level, ql.arch.type, ql.os.type)

            # emu_opt_name is based on level
            if emu_level_name == "IPPROTO_IP":
                emu_opt_name = socket_ip_option_mapping(emu_opt, ql.arch.type, ql.os.type)
            else:
                emu_opt_name = socket_option_mapping(emu_opt, ql.arch.type, ql.os.type)

            # Fix for mips
            if ql.arch.type == QL_ARCH.MIPS:
                if emu_opt_name.endswith("_NEW") or emu_opt_name.endswith("_OLD"):
                    emu_opt_name = emu_opt_name[:-4]

        except KeyError:
            ql.log.error(f"Can't convert emu_optname {emu_opt} to host platform based optname")
            raise

        try:
            optname = getattr(socket, emu_opt_name)
        except AttributeError:
            ql.log.error(f"Can't convert emu_optname {emu_opt_name}:{emu_opt} to host platform based emu_optname")
            raise

        ql.log.debug(f"Convert emu_optname {emu_opt_name}:{emu_opt} to host platform based optname {emu_opt_name}:{optname}")

        optval = ql.os.fd[sockfd].getsockopt(level, optname, optlen)
        ql.mem.write(optval_addr, optval)
    except UcError:
        return -EFAULT

    return 0


def ql_syscall_setsockopt(ql: Qiling, sockfd, level, optname, optval_addr, optlen):
    if sockfd not in range(NR_OPEN) or ql.os.fd[sockfd] is None:
        return -EBADF

    regreturn = 0
    if optval_addr == 0:
        ql.os.fd[sockfd].setsockopt(level, optname, None, optlen)
    else:
        try:
            emu_level = level

            try:
                emu_level_name = socket_level_mapping(emu_level, ql.arch.type, ql.os.type)
            except KeyError:
                ql.log.error(f"Can't convert emu_level {emu_level} to host platform based level")
                raise

            try:
                level = getattr(socket, emu_level_name)
            except AttributeError:
                ql.log.error(f"Can't convert emu_level {emu_level_name}:{emu_level} to host platform based emu_level")
                raise

            ql.log.debug(f"Convert emu_level {emu_level_name}:{emu_level} to host platform based level {emu_level_name}:{level}")

            emu_opt = optname

            try:
                emu_level_name = socket_level_mapping(emu_level, ql.arch.type, ql.os.type)

                # emu_opt_name is based on level
                if emu_level_name == "IPPROTO_IP":
                    emu_opt_name = socket_ip_option_mapping(emu_opt, ql.arch.type, ql.os.type)
                else:
                    emu_opt_name = socket_option_mapping(emu_opt, ql.arch.type, ql.os.type)

                # Fix for mips
                if ql.arch.type == QL_ARCH.MIPS:
                    if emu_opt_name.endswith("_NEW") or emu_opt_name.endswith("_OLD"):
                        emu_opt_name = emu_opt_name[:-4]

            except KeyError:
                ql.log.error(f"Can't convert emu_optname {emu_opt} to host platform based optname")
                raise

            try:
                optname = getattr(socket, emu_opt_name)
            except AttributeError:
                ql.log.error(f"Can't convert emu_optname {emu_opt_name}:{emu_opt} to host platform based emu_optname")
                raise

            ql.log.debug(f"Convert emu_optname {emu_opt_name}:{emu_opt} to host platform based optname {emu_opt_name}:{optname}")

            optval = ql.mem.read(optval_addr, optlen)
            ql.os.fd[sockfd].setsockopt(level, optname, optval, None)

        except UcError:
            regreturn = -EFAULT

        except:
            regreturn = -1

    return regreturn


def ql_syscall_shutdown(ql: Qiling, fd: int, how: int):
    regreturn = 0

    if fd in range(NR_OPEN):
        sock = ql.os.fd[fd]

        if sock is not None:
            try:
                sock.shutdown(how)
            except:
                regreturn = -1

    return regreturn


def ql_syscall_bind(ql: Qiling, bind_fd, bind_addr, bind_addrlen):
    regreturn = 0

    if ql.arch.type == QL_ARCH.X8664:
        data = ql.mem.read(bind_addr, 8)
    else:
        data = ql.mem.read(bind_addr, bind_addrlen)

    sin_family = ql.unpack16(data[:2]) or ql.os.fd[bind_fd].family
    port, host = struct.unpack(">HI", data[2:8])
    host = ql_bin_to_ip(host)

    if not ql.os.root and port <= 1024:
        port = port + 8000

    if sin_family == 1:
        hpath, vpath = ql_unix_socket_path(ql, data[2:])
        ql.log.debug(f'binding socket to "{vpath}"')
        ql.os.fd[bind_fd].bind(hpath)

    # need a proper fix, for now ipv4 comes first
    elif sin_family == 2 and ql.os.bindtolocalhost == True:
        host = "127.0.0.1"
        ql.os.fd[bind_fd].bind((host, port))

    # IPv4 should comes first
    elif ql.os.ipv6 == True and sin_family == 10 and ql.os.bindtolocalhost == True:
        host = "::1"
        ql.os.fd[bind_fd].bind((host, port))

    elif ql.os.bindtolocalhost == False:
        ql.os.fd[bind_fd].bind((host, port))

    else:
        regreturn = -1

    if ql.code:
        regreturn = 0

    if sin_family == 1:
        ql.log.debug("bind(%d, %s, %d) = %d" % (bind_fd, vpath, bind_addrlen, regreturn))
    else:
        ql.log.debug("bind(%d,%s:%d,%d) = %d" % (bind_fd, host, port, bind_addrlen,regreturn))
        ql.log.debug("syscall bind host: %s and port: %i sin_family: %i" % (ql_bin_to_ip(host), port, sin_family))

    return regreturn


def ql_syscall_getsockname(ql: Qiling, sockfd: int, addr: int, addrlenptr: int):
    if 0 <= sockfd < NR_OPEN:
        socket = ql.os.fd[sockfd]

        if isinstance(socket, ql_socket):
            host, port = socket.getpeername()

            data = struct.pack("<h", int(socket.family))
            data += struct.pack(">H", port)
            data += ipaddress.ip_address(host).packed

            addrlen = ql.mem.read_ptr(addrlenptr)

            ql.mem.write(addr, data[:addrlen])
            regreturn = 0
        else:
            regreturn = -EPERM
    else:
        regreturn = -EPERM

    ql.log.debug("getsockname(%d, 0x%x, 0x%x) = %d" % (sockfd, addr, addrlenptr, regreturn))
    return regreturn


def ql_syscall_getpeername(ql: Qiling, sockfd: int, addr: int, addrlenptr: int):
    if 0 <= sockfd < NR_OPEN:
        socket = ql.os.fd[sockfd]

        if isinstance(socket, ql_socket):
            host, port = socket.getpeername()

            data = struct.pack("<h", int(socket.family))
            data += struct.pack(">H", port)
            data += ipaddress.ip_address(host).packed

            addrlen = ql.mem.read_ptr(addrlenptr)

            ql.mem.write(addr, data[:addrlen])
            regreturn = 0
        else:
            regreturn = -EPERM
    else:
        regreturn = -EPERM

    ql.log.debug("getpeername(%d, 0x%x, 0x%x) = %d" % (sockfd, addr, addrlenptr, regreturn))
    return regreturn


def ql_syscall_listen(ql: Qiling, sockfd: int, backlog: int):
    if sockfd not in range(NR_OPEN):
        return -1

    sock = ql.os.fd[sockfd]

    if sock is None:
        return -1

    try:
        sock.listen(backlog)
    except:
        if ql.verbose >= QL_VERBOSE.DEBUG:
            raise

        return -1

    return 0


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

        if conn is None:
            return -1

        idx = next((i for i in range(NR_OPEN) if ql.os.fd[i] is None), -1)

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
            ql.mem.write_ptr(accept_addrlen, 16, 4)
    except:
        if ql.verbose >= QL_VERBOSE.DEBUG:
            raise
        regreturn = -1

    return regreturn


def ql_syscall_recv(ql: Qiling, sockfd: int, buf: int, length: int, flags: int):
    if sockfd not in range(NR_OPEN):
        return -1

    sock = ql.os.fd[sockfd]

    if sock is None:
        return -1

    content = sock.recv(length, flags)

    if content:
        ql.log.debug("recv() CONTENT:")
        ql.log.debug("%s" % content)

    ql.mem.write(buf, content)

    return len(content)


def ql_syscall_send(ql: Qiling, sockfd: int, buf: int, length: int, flags: int):
    if sockfd not in range(NR_OPEN):
        return -1

    sock = ql.os.fd[sockfd]

    if sock is None:
        return -1

    try:
        content = bytes(ql.mem.read(buf, length))
        regreturn = sock.send(content, flags)
    except:
        regreturn = 0
        ql.log.info(sys.exc_info()[0])

        if ql.verbose >= QL_VERBOSE.DEBUG:
            raise

    return regreturn


def ql_syscall_recvmsg(ql: Qiling, sockfd: int, msg_addr: int, flags: int):
    regreturn = 0
    if sockfd not in range(NR_OPEN) and ql.os.fd[sockfd] is not None:
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

def ql_syscall_recvfrom(ql: Qiling, sockfd: int, buf: int, length: int, flags: int, addr: int, addrlen: int):
    if sockfd not in range(NR_OPEN):
        return -1

    sock = ql.os.fd[sockfd]

    if sock is None:
        return -1

    SOCK_STREAM = 1

    # For x8664, recvfrom() is called finally when calling recv() in TCP communications
    if sock.socktype == SOCK_STREAM:
        return ql_syscall_recv(ql, sockfd, buf, length, flags)

    tmp_buf, tmp_addr = sock.recvfrom(length, flags)

    if tmp_buf:
        ql.log.debug("recvfrom() CONTENT:")
        ql.log.debug("%s" % tmp_buf)

    sin_family = int(sock.family)
    sockaddr_out = struct.pack("<h", sin_family)

    if sin_family == 1:
        # Abstract Unix socket path is not filled in recvfrom
        ql.log.debug(f"recvfrom() path is '{tmp_addr or 'UNIX ABSTRACT NAMESPACE'}'")
        if tmp_addr:
            sockaddr_out += tmp_addr.encode()
    else:
        ql.log.debug("recvfrom() addr is %s:%d" % (tmp_addr[0], tmp_addr[1]))
        sockaddr_out += struct.pack(">H", tmp_addr[1])
        sockaddr_out += ipaddress.ip_address(tmp_addr[0]).packed
        addrlen = ql.mem.read_ptr(addrlen)
        sockaddr_out = sockaddr_out[:addrlen]

    if addr:
        ql.mem.write(addr, sockaddr_out)
    ql.mem.write(buf, tmp_buf)

    return len(tmp_buf)


def ql_syscall_sendto(ql: Qiling, sockfd: int, sendto_buf, sendto_len, sendto_flags, sendto_addr, sendto_addrlen):
    if sockfd not in range(NR_OPEN):
        return -1

    sock = ql.os.fd[sockfd]

    if sock is None:
        return -1

    SOCK_STREAM = 1

    # For x8664, sendto() is called finally when calling send() in TCP communications
    if sock.socktype == SOCK_STREAM:
        return ql_syscall_send(ql, sockfd, sendto_buf, sendto_len, sendto_flags)

    regreturn = 0

    try:
        ql.log.debug("debug sendto() start")
        tmp_buf = ql.mem.read(sendto_buf, sendto_len)

        if ql.arch.type== QL_ARCH.X8664:
            data = ql.mem.read(sendto_addr, 8)
        else:
            data = ql.mem.read(sendto_addr, sendto_addrlen)

        sin_family, = struct.unpack("<h", data[:2])
        port, host = struct.unpack(">HI", data[2:8])
        host = ql_bin_to_ip(host)

        ql.log.debug("fd is " + str(sockfd))
        ql.log.debug("sendto() CONTENT:")
        ql.log.debug("%s" % tmp_buf)
        ql.log.debug("sendto() flag is " + str(sendto_flags))
        ql.log.debug("sendto() len is " + str(sendto_len))

        if sin_family == 1:
            hpath, vpath = ql_unix_socket_path(ql, data[2:])

            ql.log.debug("sendto() path is " + str(vpath))
            regreturn = sock.sendto(bytes(tmp_buf), sendto_flags, hpath)
        else:
            ql.log.debug("sendto() addr is %s:%d" % (host, port))
            regreturn = sock.sendto(bytes(tmp_buf), sendto_flags, (host, port))
        ql.log.debug("debug sendto end")
    except:
        ql.log.debug(sys.exc_info()[0])

        if ql.verbose >= QL_VERBOSE.DEBUG:
            raise

    return regreturn
