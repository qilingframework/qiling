#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
import os

from qiling.exception import *

try:
    import fcntl
except ImportError:
    pass
import socket

class ql_socket:
    def __init__(self, socket):
        self.__fd = socket.fileno()
        self.__socket = socket
    
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
    
    def ioctl(self, ioctl_cmd, ioctl_arg):
        try:
            return fcntl.ioctl(self.__fd, ioctl_cmd, ioctl_arg)
        except Exception:
            pass    
    
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
    
    def accept(self):
        con, addr = self.__socket.accept()
        new_ql_socket = ql_socket(con)
        return new_ql_socket, addr
    
    def recv(self, recv_len, recv_flags):
        return self.__socket.recv(recv_len, recv_flags)
    
    def send(self, send_buf, send_flags):
        return self.__socket.send(send_buf, send_flags)

    @property
    def family(self):
        return self.__socket.family
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
    
    def ioctl(self, ioctl_cmd, ioctl_arg):
        try:
            return fcntl.ioctl(self.__fd, ioctl_cmd, ioctl_arg)
        except Exception:
            pass    
    
    def dup(self):
        new_fd = os.dup(self.__fd)
        new_ql_pipe = ql_pipe(new_fd)
        return new_ql_pipe
