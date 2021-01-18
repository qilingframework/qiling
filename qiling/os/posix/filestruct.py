#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#
import os
import socket
import fcntl

from qiling.exception import *

class ql_socket:
    def __init__(self, socket):
        self.__fd = socket.fileno()
        self.__socket = socket

    def __getstate__(self, *args, **kwargs):

        _state = self.__dict__.copy()

        _state["_ql_socket__socket"] = {
                "family": self.__dict__["_ql_socket__socket"].family,
                "type": self.__dict__["_ql_socket__socket"].type,
                "proto": self.__dict__["_ql_socket__socket"].proto,
                "laddr": self.__dict__["_ql_socket__socket"].getsockname(),
                }

        return _state

    def __setstate__(self, state):
        self.__dict__ = state
    
    @classmethod
    def open(self, socket_domain, socket_type, socket_protocol, opts=None):
        s = socket.socket(socket_domain, socket_type, socket_protocol)
        if opts:
            s.setsockopt(*opts)
        return self(s)

    def read(self, read_len):
        return os.read(self.__fd, read_len)
    
    def write(self, write_buf):
        return os.write(self.__fd, write_buf)
    
    def fileno(self):
        return self.__fd
    
    def close(self):
        return os.close(self.__fd)
    
    def fcntl(self, fcntl_cmd, fcntl_arg):
        return fcntl.fcntl(self.__fd, fcntl_cmd, fcntl_arg)

    def ioctl(self, ioctl_cmd, ioctl_arg):
        return fcntl.ioctl(self.__fd, ioctl_cmd, ioctl_arg)
    
    def dup(self):
        new_s = self.__socket.dup()
        new_ql_socket = ql_socket(new_s)
        return new_ql_socket

    def connect(self, connect_addr):
        return self.__socket.connect(connect_addr)
    
    def shutdown(self, shutdown_how):
        return self.__socket.shutdown(shutdown_how)
    
    def bind(self, bind_addr):
        return self.__socket.bind(bind_addr)
    
    def listen(self, listen_num):
        return self.__socket.listen(listen_num)

    def getsockname(self):
        return self.__socket.getsockname()
        
    def getpeername(self):
        return self.__socket.getpeername()
    
    def accept(self):
        try:
            con, addr = self.__socket.accept()
            new_ql_socket = ql_socket(con)
        except BlockingIOError:
            # For support non-blocking sockets
            return None, None
        return new_ql_socket, addr
    
    def recv(self, recv_len, recv_flags):
        return self.__socket.recv(recv_len, recv_flags)
    
    def send(self, send_buf, send_flags):
        return self.__socket.send(send_buf, send_flags)

    def recvfrom(self, recvfrom_len, recvfrom_flags):
        return self.__socket.recvfrom(recvfrom_len, recvfrom_flags)

    def sendto(self, sendto_buf, sendto_flags, sendto_addr):
        return self.__socket.sendto(sendto_buf, sendto_flags, sendto_addr)

    @property
    def family(self):
        return self.__socket.family

    @property
    def socktype(self):
        return self.__socket.type

    @property
    def socket(self):
        return self.__socket

    # def __getattr__(self,name):  
    #     if name in dir(self.__socket):
    #         return getattr(self.__socket, name)
    #     else:
    #         raise AttributeError("A instance has no attribute '%s'" % name)

class ql_pipe:
    def __init__(self, fd):
        self.__fd = fd

    @classmethod
    def open(self):
        r, w = os.pipe()
        return (self(r), self(w))

    def read(self, read_len):
        return os.read(self.__fd, read_len)
    
    def write(self, write_buf):
        return os.write(self.__fd, write_buf)
    
    def fileno(self):
        return self.__fd

    def close(self):
        return os.close(self.__fd)
    
    def fcntl(self, fcntl_cmd, fcntl_arg):
        return fcntl.fcntl(self.__fd, fcntl_cmd, fcntl_arg)

    def ioctl(self, ioctl_cmd, ioctl_arg):
        return fcntl.ioctl(self.__fd, ioctl_cmd, ioctl_arg)
    
    def dup(self):
        new_fd = os.dup(self.__fd)
        new_ql_pipe = ql_pipe(new_fd)
        return new_ql_pipe


