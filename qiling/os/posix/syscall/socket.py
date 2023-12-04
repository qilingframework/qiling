#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ipaddress
import socket
from typing import Optional, Tuple

from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
from qiling.os.posix.const_mapping import socket_type_mapping, socket_level_mapping, socket_domain_mapping, socket_ip_option_mapping, socket_tcp_option_mapping, socket_option_mapping
from qiling.os.posix.const import *
from qiling.os.posix.filestruct import ql_socket
from qiling.os.posix.structs import *


AF_UNIX = 1
AF_INET = 2
AF_INET6 = 10

SOCK_STREAM = 1
SOCK_DGRAM = 2
SOCK_SEQPACKET = 5

def inet_aton(ipaddr: str) -> int:
    # ipdata = bytes(int(a, 0) for a in ipaddr.split('.', 4))
    ipdata = ipaddress.IPv4Address(ipaddr).packed

    return int.from_bytes(ipdata, byteorder='big')


def inet6_aton(ipaddr: str) -> Tuple[int, ...]:
    abytes = ipaddress.IPv6Address(ipaddr).packed

    return tuple(abytes)


def inet_htoa(ql: Qiling, addr: int) -> str:
    abytes = ql.pack32(addr)

    return ipaddress.IPv4Address(abytes).compressed


def inet_ntoa(addr: int) -> str:
    abytes = addr.to_bytes(length=4, byteorder='big')

    return ipaddress.IPv4Address(abytes).compressed


def inet6_htoa(ql: Qiling, addr: bytes) -> str:
    # TODO: swap addr bytes order according to ql.arch.endian?

    return ipaddress.IPv6Address(addr).compressed


def inet6_ntoa(addr: bytes) -> str:
    # if addr arg is not strictly a bytes object, convert it to bytes
    if not isinstance(addr, bytes):
        addr = bytes(addr)

    return ipaddress.IPv6Address(addr).compressed


def ntohs(ql: Qiling, nval: int) -> int:
    ebdata = nval.to_bytes(length=2, byteorder='big')

    return ql.unpack16(ebdata)


def htons(ql: Qiling, hval: int) -> int:
    ndata = ql.pack16(hval)

    return int.from_bytes(ndata, byteorder='big')


def ql_unix_socket_path(ql: Qiling, sun_path: bytearray) -> Tuple[str, str]:
    vpath, _, _ = sun_path.partition(b'\x00')

    # an abstract Unix namespace?
    if not vpath:
        # TODO: isolate from host namespace
        # TODO: Windows
        ql.log.warning(f'Beware! Usage of hosts abstract socket namespace {bytes(sun_path)}')

        return (sun_path.decode(), '')

    vpath = ql.os.path.virtual_abspath(vpath.decode())
    hpath = ql.os.path.virtual_to_host_path(vpath)

    return (hpath, vpath)


def __host_socket_type(vsock_type: int, arch_type: QL_ARCH) -> int:
    """Convert emulated socket type value to a host socket type.
    """

    try:
        vsock_type_name = socket_type_mapping(vsock_type, arch_type)
    except KeyError:
        raise NotImplementedError(f'Could not convert emulated socket type {vsock_type} to a socket type name')

    try:
        hsock_type = getattr(socket, vsock_type_name)
    except AttributeError:
        raise NotImplementedError(f'Could not convert emulated socket type name {vsock_type_name} to a host socket type')

    return hsock_type


def __host_socket_level(vsock_level: int, arch_type: QL_ARCH) -> int:
    """Convert emulated socket level value to a host socket level.
    """

    try:
        vsock_level_name = socket_level_mapping(vsock_level, arch_type)
    except KeyError:
        raise NotImplementedError(f'Could not convert emulated socket level {vsock_level} to a socket level name')

    try:
        hsock_level = getattr(socket, vsock_level_name)
    except AttributeError:
        raise NotImplementedError(f'Could not convert emulated socket level name {vsock_level_name} to a host socket level')

    return hsock_level


def __host_socket_option(vsock_level: int, vsock_opt: int, arch_type: QL_ARCH, os_type: QL_OS) -> int:
    """Convert emulated socket option value to a host socket option.
    """

    try:
        if vsock_level == 0x0000:  # IPPROTO_IP
            vsock_opt_name = socket_ip_option_mapping(vsock_opt, arch_type, os_type)

        elif vsock_level == 0x0006:  # IPPROTO_TCP
            vsock_opt_name = socket_tcp_option_mapping(vsock_opt, arch_type)

        else:
            vsock_opt_name = socket_option_mapping(vsock_opt, arch_type)

        # Fix for mips
        if arch_type == QL_ARCH.MIPS:
            if vsock_opt_name.endswith(('_NEW', '_OLD')):
                vsock_opt_name = vsock_opt_name[:-4]

    except KeyError:
        raise NotImplementedError(f'Could not convert emulated socket option {vsock_opt} to a socket option name')

    try:
        hsock_opt = getattr(socket, vsock_opt_name)
    except AttributeError:
        raise NotImplementedError(f'Could not convert emulated socket option name {vsock_opt_name} to a host socket option')

    return hsock_opt


def ql_syscall_socket(ql: Qiling, domain: int, socktype: int, protocol: int):
    idx = next((i for i in range(NR_OPEN) if ql.os.fd[i] is None), -1)

    if idx != -1:
        # ql_socket.open should use host platform based socket type
        vsock_type = socktype
        hsock_type = __host_socket_type(vsock_type, ql.arch.type)

        ql.log.debug(f'Converted emulated socket type {vsock_type} to host socket type {hsock_type}')

        try:
            sock = ql_socket.open(domain, hsock_type, protocol)

            # set REUSEADDR options under debug mode
            if ql.verbose >= QL_VERBOSE.DEBUG:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # May raise error: Protocol not supported
        except OSError as e:
            ql.log.debug(f'Error opening socket: {e}')
            idx = -1
        else:
            ql.os.fd[idx] = sock

    s_domain = socket_domain_mapping(domain, ql.arch.type, ql.os.type)
    s_socktype = socket_type_mapping(socktype, ql.arch.type)
    ql.log.debug("socket(%s, %s, %s) = %d" % (s_domain, s_socktype, protocol, idx))

    return idx


def ql_syscall_socketpair(ql: Qiling, domain: int, socktype: int, protocol: int, sv: int):
    unpopulated_fd = (i for i in range(NR_OPEN) if ql.os.fd[i] is None)

    idx1 = next(unpopulated_fd, -1)
    idx2 = next(unpopulated_fd, -1)

    regreturn = -1

    if (idx1 != -1) and (idx2 != -1):
        # ql_socket.socketpair should use host platform based socket type
        vsock_type = socktype
        hsock_type = __host_socket_type(vsock_type, ql.arch.type)

        ql.log.debug(f'Converted emulated socket type {vsock_type} to host socket type {hsock_type}')

        try:
            sock1, sock2 = ql_socket.socketpair(domain, hsock_type, protocol)

        # May raise error: Protocol not supported
        except OSError as e:
            ql.log.debug(f'{e}: {domain=}, {socktype=}, {protocol=}, {sv=}')
            regreturn = -1

        else:
            ql.os.fd[idx1] = sock1
            ql.os.fd[idx2] = sock2

            # save fd to &sv
            ql.mem.write_ptr(sv + 0, idx1)
            ql.mem.write_ptr(sv + 4, idx2)

            regreturn = 0

    s_domain = socket_domain_mapping(domain, ql.arch.type, ql.os.type)
    s_type = socket_type_mapping(socktype, ql.arch.type)
    ql.log.debug("socketpair(%s, %s, %d, %d) = %d" % (s_domain, s_type, protocol, sv, regreturn))

    return regreturn


def ql_syscall_connect(ql: Qiling, sockfd: int, addr: int, addrlen: int):
    if sockfd not in range(NR_OPEN):
        return -1

    sock: Optional[ql_socket] = ql.os.fd[sockfd]

    if sock is None:
        return -1

    data = ql.mem.read(addr, addrlen)

    abits = ql.arch.bits
    endian = ql.arch.endian

    sockaddr = make_sockaddr(abits, endian)
    sockaddr_obj = sockaddr.from_buffer(data)

    dest = None
    regreturn = -1

    if sock.family != sockaddr_obj.sa_family:
        return -1

    if sock.family == AF_UNIX:
        hpath, vpath = ql_unix_socket_path(ql, data[2:])

        # TODO: support connecting to fs_mapped unix sockets
        ql.log.debug(f'Connecting to "{vpath}"')
        dest = hpath

    elif sock.family == AF_INET:
        sockaddr_in = make_sockaddr_in(abits, endian)
        sockaddr_obj = sockaddr_in.from_buffer(data)

        port = ntohs(ql, sockaddr_obj.sin_port)
        host = inet_htoa(ql, sockaddr_obj.sin_addr.s_addr)

        ql.log.debug(f'Connecting to {host}:{port}')
        dest = (host, port)

    elif sock.family == AF_INET6 and ql.os.ipv6:
        sockaddr_in6 = make_sockaddr_in6(abits, endian)
        sockaddr_obj = sockaddr_in6.from_buffer(data)

        port = ntohs(ql, sockaddr_obj.sin6_port)
        host = inet6_htoa(ql, sockaddr_obj.sin6_addr.s6_addr)

        ql.log.debug(f'Connecting to {host}:{port}')
        dest = (host, port)

    if dest is not None:
        try:
            sock.connect(dest)
        except (ConnectionError, FileNotFoundError):
            regreturn = -1
        else:
            regreturn = 0

    return regreturn


def ql_syscall_getsockopt(ql: Qiling, sockfd: int, level: int, optname: int, optval_addr: int, optlen_addr: int):
    if sockfd not in range(NR_OPEN):
        return -1

    sock: Optional[ql_socket] = ql.os.fd[sockfd]

    if sock is None:
        return -1

    vsock_level = level
    hsock_level = __host_socket_level(vsock_level, ql.arch.type)

    ql.log.debug(f'Converted emulated socket level {vsock_level} to host socket level {hsock_level}')

    vsock_opt = optname
    hsock_opt = __host_socket_option(vsock_level, vsock_opt, ql.arch.type, ql.os.type)

    ql.log.debug(f'Converted emulated socket option {vsock_opt} to host socket option {hsock_opt}')

    optlen = min(ql.unpack32s(ql.mem.read(optlen_addr, 4)), 1024)

    if optlen < 0:
        return -1

    try:
        optval = sock.getsockopt(hsock_level, hsock_opt, optlen)
    except (ConnectionError, OSError):
        return -1

    ql.mem.write(optval_addr, optval)

    return 0


def ql_syscall_setsockopt(ql: Qiling, sockfd: int, level: int, optname: int, optval_addr: int, optlen: int):
    if sockfd not in range(NR_OPEN):
        return -1

    sock: Optional[ql_socket] = ql.os.fd[sockfd]

    if sock is None:
        return -1

    if optval_addr == 0:
        sock.setsockopt(level, optname, None, optlen)

    else:
        vsock_level = level
        hsock_level = __host_socket_level(vsock_level, ql.arch.type)

        ql.log.debug(f'Converted emulated socket level {vsock_level} to host socket level {hsock_level}')

        vsock_opt = optname
        hsock_opt = __host_socket_option(vsock_level, vsock_opt, ql.arch.type, ql.os.type)

        ql.log.debug(f'Converted emulated socket option {vsock_opt} to host socket option {hsock_opt}')

        optval = ql.mem.read(optval_addr, optlen)

        try:
            sock.setsockopt(hsock_level, hsock_opt, optval)
        except (ConnectionError, OSError):
            return -1

    return 0


def ql_syscall_shutdown(ql: Qiling, sockfd: int, how: int):
    if sockfd not in range(NR_OPEN):
        return -1

    sock: Optional[ql_socket] = ql.os.fd[sockfd]

    if sock is None:
        return -1

    try:
        sock.shutdown(how)
    except ConnectionError:
        return -1

    return 0


def ql_syscall_bind(ql: Qiling, sockfd: int, addr: int, addrlen: int):
    if sockfd not in range(NR_OPEN):
        return -1

    sock: Optional[ql_socket] = ql.os.fd[sockfd]

    if sock is None:
        return -1

    data = ql.mem.read(addr, addrlen)

    abits = ql.arch.bits
    endian = ql.arch.endian

    sockaddr = make_sockaddr(abits, endian)
    sockaddr_obj = sockaddr.from_buffer(data)

    sa_family = sockaddr_obj.sa_family

    dest = None
    regreturn = -1

    if sa_family == AF_UNIX:
        hpath, vpath = ql_unix_socket_path(ql, data[2:])

        ql.log.debug(f'Binding socket to "{vpath}"')
        dest = hpath

    elif sa_family == AF_INET:
        sockaddr = make_sockaddr_in(abits, endian)
        sockaddr_obj = sockaddr.from_buffer(data)

        port = ntohs(ql, sockaddr_obj.sin_port)
        host = inet_ntoa(sockaddr_obj.sin_addr.s_addr)

        if ql.os.bindtolocalhost:
            host = '127.0.0.1'

        if not ql.os.root and port <= 1024:
            port = port + 8000

        ql.log.debug(f'Binding socket to {host}:{port}')
        dest = (host, port)

    elif sa_family == AF_INET6 and ql.os.ipv6:
        sockaddr_in6 = make_sockaddr_in6(abits, endian)
        sockaddr_obj = sockaddr_in6.from_buffer(data)

        port = ntohs(ql, sockaddr_obj.sin6_port)
        host = inet6_ntoa(sockaddr_obj.sin6_addr.s6_addr)

        if ql.os.bindtolocalhost:
            host = '::1'

        if not ql.os.root and port <= 1024:
            port = port + 8000

        ql.log.debug(f'Binding socket to {host}:{port}')
        dest = (host, port)

    if dest is not None:
        try:
            sock.bind(dest)
        except (ConnectionError, FileNotFoundError):
            regreturn = -1
        else:
            regreturn = 0

    return regreturn


def ql_syscall_getsockname(ql: Qiling, sockfd: int, addr: int, addrlenptr: int):
    if sockfd not in range(NR_OPEN):
        return -1

    sock: Optional[ql_socket] = ql.os.fd[sockfd]

    if sock is None:
        return -1

    addrlen = ql.mem.read_ptr(addrlenptr) if addrlenptr else 0

    abits = ql.arch.bits
    endian = ql.arch.endian

    sockname = sock.getsockname()
    obj = None

    if sock.family == AF_UNIX:
        hpath = sockname
        vpath = ql.os.path.host_to_virtual_path(hpath)

        if addrlen:
            # addrlen indicates the total obj size allowed to be written.
            # that already includes the family field (2) and the path null
            # terminator (1)
            vpath = vpath[:addrlen - 2 - 1]

        sockaddr_un = make_sockaddr_un(abits, endian, len(vpath) + 1)

        obj = sockaddr_un()
        obj.sun_family = AF_UNIX
        obj.sun_path = vpath.encode() + b'\x00'

    elif sock.family == AF_INET:
        sockaddr_in = make_sockaddr_in(abits, endian)
        host, port = sockname

        obj = sockaddr_in()
        obj.sin_family = AF_INET
        obj.sin_port = htons(ql, port)
        obj.sin_addr.s_addr = inet_aton(str(host))

    elif sock.family == AF_INET6 and ql.os.ipv6:
        sockaddr_in6 = make_sockaddr_in6(abits, endian)
        host, port = sockname

        obj = sockaddr_in6()
        obj.sin6_family = AF_INET6
        obj.sin6_port = htons(ql, port)
        obj.sin6_addr.s6_addr = inet6_aton(str(host))

    if obj:
        objsize = obj.sizeof()

        if objsize <= addrlen:
            obj.save_to(ql.mem, addr)

        if addrlenptr:
            ql.mem.write_ptr(addrlenptr, objsize)

    ql.log.debug("getsockname(%d, %#x, %#x) = %d" % (sockfd, addr, addrlenptr, 0))

    return 0


def ql_syscall_getpeername(ql: Qiling, sockfd: int, addr: int, addrlenptr: int):
    if sockfd not in range(NR_OPEN):
        return -1

    sock: Optional[ql_socket] = ql.os.fd[sockfd]

    if sock is None:
        return -1

    addrlen = ql.mem.read_ptr(addrlenptr) if addrlenptr else 0

    abits = ql.arch.bits
    endian = ql.arch.endian

    peername = sock.getpeername()
    obj = None

    if sock.family == AF_UNIX:
        hpath = peername
        vpath = ql.os.path.host_to_virtual_path(hpath)

        if addrlen:
            # addrlen indicates the total obj size allowed to be written.
            # that already includes the family field (2) and the path null
            # terminator (1)
            vpath = vpath[:addrlen - 2 - 1]

        sockaddr_un = make_sockaddr_un(abits, endian, len(vpath) + 1)

        obj = sockaddr_un()
        obj.sun_family = AF_UNIX
        obj.sun_path = vpath.encode() + b'\x00'

    elif sock.family == AF_INET:
        sockaddr_in = make_sockaddr_in(abits, endian)
        host, port = peername

        obj = sockaddr_in()
        obj.sin_family = AF_INET
        obj.sin_port = htons(ql, port)
        obj.sin_addr.s_addr = inet_aton(str(host))

    elif sock.family == AF_INET6 and ql.os.ipv6:
        sockaddr_in6 = make_sockaddr_in6(abits, endian)
        host, port = peername

        obj = sockaddr_in6()
        obj.sin6_family = AF_INET6
        obj.sin6_port = htons(ql, port)
        obj.sin6_addr.s6_addr = inet6_aton(str(host))

    if obj:
        objsize = obj.sizeof()

        if objsize <= addrlen:
            obj.save_to(ql.mem, addr)

        if addrlenptr:
            ql.mem.write_ptr(addrlenptr, objsize)

    ql.log.debug("getpeername(%d, %#x, %#x) = %d" % (sockfd, addr, addrlenptr, 0))

    return 0


def ql_syscall_listen(ql: Qiling, sockfd: int, backlog: int):
    if sockfd not in range(NR_OPEN):
        return -1

    sock: Optional[ql_socket] = ql.os.fd[sockfd]

    if sock is None:
        return -1

    try:
        sock.listen(backlog)
    except ConnectionError:
        return -1

    return 0


def ql_syscall_accept(ql: Qiling, sockfd: int, addr: int, addrlenptr: int):
    if sockfd not in range(NR_OPEN):
        return -1

    sock: Optional[ql_socket] = ql.os.fd[sockfd]

    if sock is None:
        return -1

    try:
        conn, address = sock.accept()
    except ConnectionError:
        return -1

    if (conn is None) or (address is None):
        return -1

    idx = next((i for i in range(NR_OPEN) if ql.os.fd[i] is None), -1)

    if idx == -1:
        return -1

    ql.os.fd[idx] = conn

    if addr:
        addrlen = ql.mem.read_ptr(addrlenptr) if addrlenptr else 0

        abits = ql.arch.bits
        endian = ql.arch.endian

        obj = None

        if conn.family == AF_UNIX:
            hpath = address
            vpath = ql.os.path.host_to_virtual_path(hpath)

            if addrlen:
                # addrlen indicates the total obj size allowed to be written.
                # that already includes the family field (2) and the path null
                # terminator (1)
                vpath = vpath[:addrlen - 2 - 1]

            sockaddr_un = make_sockaddr_un(abits, endian, len(vpath) + 1)

            obj = sockaddr_un()
            obj.sun_family = AF_UNIX
            obj.sun_path = vpath.encode() + b'\x00'

        elif conn.family == AF_INET:
            sockaddr_in = make_sockaddr_in(abits, endian)
            host, port = address

            obj = sockaddr_in()
            obj.sin_family = AF_INET
            obj.sin_port = htons(ql, port)
            obj.sin_addr.s_addr = inet_aton(str(host))

        elif conn.family == AF_INET6 and ql.os.ipv6:
            sockaddr_in6 = make_sockaddr_in6(abits, endian)
            host, port = address

            obj = sockaddr_in6()
            obj.sin6_family = AF_INET6
            obj.sin6_port = htons(ql, port)
            obj.sin6_addr.s6_addr = inet6_aton(str(host))

        if obj:
            objsize = obj.sizeof()

            if objsize <= addrlen:
                obj.save_to(ql.mem, addr)

            if addrlenptr:
                ql.mem.write_ptr(addrlenptr, objsize)

    return idx


def ql_syscall_recv(ql: Qiling, sockfd: int, buf: int, length: int, flags: int):
    if sockfd not in range(NR_OPEN):
        return -1

    sock: Optional[ql_socket] = ql.os.fd[sockfd]

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

    sock: Optional[ql_socket] = ql.os.fd[sockfd]

    if sock is None:
        return -1

    content = ql.mem.read(buf, length)

    try:
        regreturn = sock.send(content, flags)
    except IOError:
        regreturn = 0

    return regreturn


def ql_syscall_recvmsg(ql: Qiling, sockfd: int, msg_addr: int, flags: int):
    if sockfd not in range(NR_OPEN):
        return -1

    sock: Optional[ql_socket] = ql.os.fd[sockfd]

    if sock is None:
        return -1

    abits = ql.arch.bits
    endian = ql.arch.endian

    msghdr = make_msghdr(abits, endian)
    msg = msghdr.load_from(ql.mem, msg_addr)

    try:
        # TODO: handle the addr
        data, ancdata, mflags, addr = sock.recvmsg(msg.msg_namelen, msg.msg_controllen, flags)
    except ConnectionError:
        return -1

    iovec = make_iovec(abits, endian)
    iovec_addr = msg.msg_iov
    written = 0

    for _ in range(msg.msg_iovlen):
        with iovec.ref(ql.mem, iovec_addr) as obj:
            size = min(obj.iov_len, len(data) - written)
            ql.mem.write(obj.iov_base, data[written:written + size])

        written += size
        iovec_addr += iovec.sizeof()

    cmsghdr = make_cmsghdr(abits, endian)
    cmsg_addr = msg.msg_control

    for cmsg_level, cmsg_type, cmsg_data in ancdata:
        with cmsghdr.ref(ql.mem, cmsg_addr) as obj:
            obj.cmsg_len = len(cmsg_data)
            obj.cmsg_level = cmsg_level
            obj.cmsg_type = cmsg_type

        cmsg_addr += cmsghdr.sizeof()

        ql.mem.write(cmsg_addr, cmsg_data)
        cmsg_addr += len(cmsg_data)

    msg.msg_flags = mflags
    msg.save_to(ql.mem, msg_addr)

    return len(data)


def ql_syscall_recvfrom(ql: Qiling, sockfd: int, buf: int, length: int, flags: int, addr: int, addrlen: int):
    if sockfd not in range(NR_OPEN):
        return -1

    sock: Optional[ql_socket] = ql.os.fd[sockfd]

    if sock is None:
        return -1

    # For x8664, recvfrom() is called finally when calling recv() in TCP communications
    # calling recvfrom with a NULL addr argument is identical to calling recv, which is normally used only on a connected socket
    if sock.socktype == SOCK_STREAM or (addr == 0 and addrlen == 0):
        return ql_syscall_recv(ql, sockfd, buf, length, flags)

    data_buf, address = sock.recvfrom(length, flags)

    if data_buf:
        ql.log.debug("recvfrom() CONTENT:")
        ql.log.debug("%s" % data_buf)

    sin_family = int(sock.family)

    abits = ql.arch.bits
    endian = ql.arch.endian

    if sin_family == AF_UNIX:
        sockaddr_un = make_sockaddr_un(abits, endian, len(address) + 1)

        ql.log.debug(f'Recieve from {address or "UNIX ABSTRACT NAMESPACE"}')

        with sockaddr_un.ref(ql.mem, addr) as obj:
            obj.sun_family = AF_UNIX

            # abstract Unix socket path is not filled in recvfrom
            if address:
                obj.sun_path = address.encode() + b'\x00'

        objlen = sockaddr_un.sizeof()

    elif sin_family == AF_INET:
        sockaddr_in = make_sockaddr_in(abits, endian)
        host, port = address

        ql.log.debug(f'Recieve from {host}:{port}')

        with sockaddr_in.ref(ql.mem, addr) as obj:
            obj.sin_family = AF_INET
            obj.sin_port = htons(ql, port)
            obj.sin_addr.s_addr = inet_aton(str(host))

        objlen = sockaddr_in.sizeof()

    elif sin_family == AF_INET6 and ql.os.ipv6:
        sockaddr_in6 = make_sockaddr_in6(abits, endian)
        host, port = address

        with sockaddr_in6.ref(ql.mem, addr) as obj:
            obj.sin6_family = AF_INET6
            obj.sin6_port = htons(ql, port)
            obj.sin6_addr.s6_addr = inet6_aton(str(host))

        objlen = sockaddr_in6.sizeof()

    else:
        objlen = 0

    # FIXME: only write up to sockaddr_out bytes of obj content?
    #
    # addrlen = ql.mem.read_ptr(addrlen)
    # sockaddr_out = sockaddr_out[:addrlen]

    ql.mem.write(buf, data_buf)

    return len(data_buf)


def ql_syscall_sendto(ql: Qiling, sockfd: int, buf: int, length: int, flags: int, addr: int, addrlen: int):
    if sockfd not in range(NR_OPEN):
        return -1

    sock: Optional[ql_socket] = ql.os.fd[sockfd]

    if sock is None:
        return -1

    # if sendto is used on a connection-mode socket, the arguments addr and addrlen are ignored.
    # also, calling sendto(sockfd, buf, length, flags, NULL, 0) is equivalent to send(sockfd, buf, length, flags)
    if sock.socktype in (SOCK_STREAM, SOCK_SEQPACKET) or (addr == 0 and addrlen == 0):
        return ql_syscall_send(ql, sockfd, buf, length, flags)

    tmp_buf = ql.mem.read(buf, length)

    ql.log.debug("sendto() CONTENT:")
    ql.log.debug("%s" % tmp_buf)

    data = ql.mem.read(addr, addrlen)

    abits = ql.arch.bits
    endian = ql.arch.endian

    sockaddr = make_sockaddr(abits, endian)
    sockaddr_obj = sockaddr.from_buffer(data)

    sa_family = sockaddr_obj.sa_family

    dest = None
    regreturn = 0

    if sa_family == AF_UNIX:
        hpath, vpath = ql_unix_socket_path(ql, data[2:])

        ql.log.debug(f'Sending {len(tmp_buf):d} bytes to {vpath}')
        dest = hpath

    elif sa_family == AF_INET:
        sockaddr = make_sockaddr_in(abits, endian)
        sockaddr_obj = sockaddr.from_buffer(data)

        port = ntohs(ql, sockaddr_obj.sin_port)
        host = inet_ntoa(sockaddr_obj.sin_addr.s_addr)

        ql.log.debug(f'Sending {len(tmp_buf):d} bytes to {host}:{port}')
        dest = (host, port)

    elif sa_family == AF_INET6 and ql.os.ipv6:
        sockaddr_in6 = make_sockaddr_in6(abits, endian)
        sockaddr_obj = sockaddr_in6.from_buffer(data)

        port = ntohs(ql, sockaddr_obj.sin6_port)
        host = inet6_ntoa(sockaddr_obj.sin6_addr.s6_addr)

        ql.log.debug(f'Sending to {host}:{port}')
        dest = (host, port)

    if dest is not None:
        try:
            regreturn = sock.sendto(tmp_buf, flags, dest)
        except (ConnectionError, FileNotFoundError):
            regreturn = 0

    return regreturn
