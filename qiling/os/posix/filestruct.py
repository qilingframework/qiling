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

    def getsockname(self):
        return self.__socket.getsockname()
        
    def getpeername(self):
        return self.__socket.getpeername()
    
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

# class for stat dealing with unsupported implementations under Windows env
class Stat(object):
    def __init__(self, path):
        super().__init__()
        self.path = path
        
        self.st_dev = 0
        self.st_blksize = 0
        self.st_blocks = 0
        self.st_ino = 0
        self.st_mode = 0
        self.st_nlink = 0
        self.st_rdev = 0
        self.st_size = 0
        self.st_uid = 0
        self.st_gid = 0
        self.st_atime = 0
        self.st_mtime = 0
        self.st_ctime = 0
        
        stat_buf = os.stat(self.path)
        for name in dir(stat_buf):
            if 'st_' in name:
                setattr(self, name, getattr(stat_buf, name))

# class for Fstat dealing with unsupported implementations under Windows env
class Fstat(object):
    def __init__(self, fd):
        super().__init__()
        self.fd = fd
        
        self.st_dev = 0
        self.st_blksize = 0
        self.st_blocks = 0
        self.st_ino = 0
        self.st_mode = 0
        self.st_nlink = 0
        self.st_rdev = 0
        self.st_size = 0
        self.st_uid = 0
        self.st_gid = 0
        self.st_atime = 0
        self.st_mtime = 0
        self.st_ctime = 0
        
        fstat_buf = os.fstat(self.fd)
        for name in dir(fstat_buf):
            if 'st_' in name:
                setattr(self, name, getattr(fstat_buf, name))
        
# class for lstat dealing with unsupported implementations under Windows env
class Lstat(object):
    def __init__(self, path):
        super().__init__()
        self.path = path
        
        self.st_dev = 0
        self.st_blksize = 0
        self.st_blocks = 0
        self.st_ino = 0
        self.st_mode = 0
        self.st_nlink = 0
        self.st_rdev = 0
        self.st_size = 0
        self.st_uid = 0
        self.st_gid = 0
        self.st_atime = 0
        self.st_mtime = 0
        self.st_ctime = 0
        
        lstat_buf = os.lstat(self.path)
        for name in dir(lstat_buf):
            if 'st_' in name:
                setattr(self, name, getattr(lstat_buf, name))

