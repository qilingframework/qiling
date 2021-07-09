#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os

from qiling.exception import *
from qiling.os.posix.stat import *

try:
    import fcntl
except ImportError:
    pass
import socket


class ql_file:
    def __init__(self, path, fd):
        self.__path = path
        self.__fd = fd
        # information for syscall mmap
        self._is_map_shared = False
        self._mapped_offset = -1
        self._close_on_exec = 0

    @classmethod
    def open(self, open_path, open_flags, open_mode, dir_fd=None):
        open_mode &= 0x7FFFFFFF

        try:
            fd = os.open(open_path, open_flags, open_mode, dir_fd=dir_fd)
        except OSError as e:
            raise QlSyscallError(e.errno, e.args[1] + " : " + e.filename)
        return self(open_path, fd)

    def read(self, read_len):
        return os.read(self.__fd, read_len)

    def write(self, write_buf):
        return os.write(self.__fd, write_buf)

    def fileno(self):
        return self.__fd

    def lseek(self, lseek_offset, lseek_origin=os.SEEK_SET):
        return os.lseek(self.__fd, lseek_offset, lseek_origin)

    def close(self):
        return os.close(self.__fd)

    def fstat(self):
        return Fstat(self.__fd)

    def fcntl(self, fcntl_cmd, fcntl_arg):
        try:
            return fcntl.fcntl(self.__fd, fcntl_cmd, fcntl_arg)
        except Exception:
            pass

    def ioctl(self, ioctl_cmd, ioctl_arg):
        try:
            return fcntl.ioctl(self.__fd, ioctl_cmd, ioctl_arg)
        except Exception:
            pass

    def tell(self):
        return self.lseek(0, os.SEEK_CUR)

    def dup(self):
        new_fd = os.dup(self.__fd)
        new_ql_file = ql_file(self.__path, new_fd)
        return new_ql_file

    def readline(self, end=b"\n"):
        ret = b""
        while True:
            c = self.read(1)
            ret += c
            if c == end:
                break
        return ret

    @property
    def name(self):
        return self.__path

    @property
    def close_on_exec(self):
        return self._close_on_exec

    @close_on_exec.setter
    def close_on_exec(self, value: int):
        self._close_on_exec = value
