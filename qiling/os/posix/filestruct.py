#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#
import os
from socket import socket, AddressFamily, SocketKind, socketpair
from typing import Union

try:
    import fcntl
except ImportError:
    pass

class ql_socket:
    def __init__(self, socket: socket):
        self.__fd = socket.fileno()
        self.__socket = socket

    def __getstate__(self, *args, **kwargs):
        _state = self.__dict__.copy()

        fname = f'_{self.__class__.__name__}__socket'
        sock = self.__dict__[fname]

        _state[fname] = {
            "family" : sock.family,
            "type"   : sock.type,
            "proto"  : sock.proto,
            "laddr"  : sock.getsockname(),
        }

        return _state

    def __setstate__(self, state):
        self.__dict__ = state

    @classmethod
    def open(cls, domain: Union[AddressFamily, int], socktype: Union[SocketKind, int], protocol: int):
        s = socket(domain, socktype, protocol)

        return cls(s)

    @classmethod
    def socketpair(cls, domain: Union[AddressFamily, int], socktype: Union[SocketKind, int], protocol: int):
        a, b = socketpair(domain, socktype, protocol)

        return cls(a), cls(b)

    def read(self, length: int) -> bytes:
        return os.read(self.__fd, length)

    def write(self, data: bytes) -> int:
        return os.write(self.__fd, data)

    def fileno(self) -> int:
        return self.__fd

    def close(self) -> None:
        os.close(self.__fd)

    def fcntl(self, cmd, arg):
        try:
            return fcntl.fcntl(self.__fd, cmd, arg)
        except Exception:
            pass

    def ioctl(self, cmd, arg):
        # might throw an OSError
        return fcntl.ioctl(self.__fd, cmd, arg)

    def dup(self) -> 'ql_socket':
        new_s = self.__socket.dup()

        return ql_socket(new_s)

    def connect(self, address) -> None:
        self.__socket.connect(address)

    def shutdown(self, how: int) -> None:
        return self.__socket.shutdown(how)

    def bind(self, address) -> None:
        return self.__socket.bind(address)

    def listen(self, backlog: int) -> None:
        return self.__socket.listen(backlog)

    def getsockname(self):
        return self.__socket.getsockname()

    def getpeername(self):
        return self.__socket.getpeername()

    def getsockopt(self, level: int, optname: int, buflen: int):
        return self.__socket.getsockopt(level, optname, buflen)

    def setsockopt(self, level: int, optname: int, value: Union[int, bytes, None], optlen: int = 0) -> None:
        if value is None:
            self.__socket.setsockopt(level, optname, None, optlen)
        else:
            self.__socket.setsockopt(level, optname, value)

    def accept(self):
        try:
            con, addr = self.__socket.accept()
        except BlockingIOError:
            # For support non-blocking sockets
            addr = None
            new_ql_socket = None
        else:
            new_ql_socket = ql_socket(con)

        return new_ql_socket, addr

    def recv(self, bufsize: int, flags: int) -> bytes:
        return self.__socket.recv(bufsize, flags)

    def send(self, data, flags: int) -> int:
        return self.__socket.send(data, flags)

    def recvmsg(self, bufsize: int, ancbufsize: int, flags: int):
        return self.__socket.recvmsg(bufsize, ancbufsize, flags)

    def recvfrom(self, bufsize: int, flags: int):
        return self.__socket.recvfrom(bufsize, flags)

    def sendto(self, sendto_buf, sendto_flags, sendto_addr):
        return self.__socket.sendto(sendto_buf, sendto_flags, sendto_addr)

    @property
    def family(self) -> AddressFamily:
        return self.__socket.family

    @property
    def socktype(self) -> SocketKind:
        return self.__socket.type

    @property
    def socket(self) -> socket:
        return self.__socket

    # def __getattr__(self,name):  
    #     if name in dir(self.__socket):
    #         return getattr(self.__socket, name)
    #     else:
    #         raise AttributeError("A instance has no attribute '%s'" % name)

class ql_pipe:
    def __init__(self, fd: int):
        self.__fd = fd

    @classmethod
    def open(cls):
        r, w = os.pipe()

        return (cls(r), cls(w))

    def read(self, length: int) -> bytes:
        return os.read(self.__fd, length)

    def write(self, data: bytes) -> int:
        return os.write(self.__fd, data)

    def fileno(self) -> int:
        return self.__fd

    def close(self) -> None:
        os.close(self.__fd)

    def fcntl(self, cmd, arg):
        try:
            return fcntl.fcntl(self.__fd, cmd, arg)
        except Exception:
            pass

    def ioctl(self, cmd, arg):
        try:
            return fcntl.ioctl(self.__fd, cmd, arg)
        except Exception:
            pass

    def dup(self) -> 'ql_pipe':
        new_fd = os.dup(self.__fd)

        return ql_pipe(new_fd)
