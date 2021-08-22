#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os
from typing import AnyStr

from qiling.exception import *
from qiling.os.posix.stat import *

try:
    import fcntl
except ImportError:
    pass

class ql_file:
    def __init__(self, path: AnyStr, fd: int):
        self.__path = path
        self.__fd = fd
        # information for syscall mmap
        self._is_map_shared = False
        self._mapped_offset = -1
        self._close_on_exec = 0

    @classmethod
    def open(cls, open_path: AnyStr, open_flags: int, open_mode: int, dir_fd: int = None):
        open_mode &= 0x7fffffff

        try:
            fd = os.open(open_path, open_flags, open_mode, dir_fd=dir_fd)
        except OSError as e:
            raise QlSyscallError(e.errno, e.args[1] + ' : ' + e.filename)

        return cls(open_path, fd)

    def read(self, read_len: int) -> bytes:
        return os.read(self.__fd, read_len)

    def write(self, write_buf: bytes) -> int:
        return os.write(self.__fd, write_buf)

    def fileno(self) -> int:
        return self.__fd

    def lseek(self, lseek_offset: int, lseek_origin: int = os.SEEK_SET) -> int:
        return os.lseek(self.__fd, lseek_offset, lseek_origin)

    def close(self) -> None:
        os.close(self.__fd)

    def fstat(self):
        return Fstat(self.__fd)

    def fcntl(self, fcntl_cmd: int, fcntl_arg):
        try:
            return fcntl.fcntl(self.__fd, fcntl_cmd, fcntl_arg)
        except Exception:
            pass

    def ioctl(self, ioctl_cmd, ioctl_arg):
        try:
            return fcntl.ioctl(self.__fd, ioctl_cmd, ioctl_arg)
        except Exception:
            pass

    def tell(self) -> int:
        return self.lseek(0, os.SEEK_CUR)

    def dup(self):
        new_fd = os.dup(self.__fd)

        return ql_file(self.__path, new_fd)

    def readline(self, end: bytes = b'\n') -> bytes:
        ret = bytearray()

        while not ret.endswith(end):
            ret.extend(self.read(1))

        return bytes(ret)

    @property
    def name(self):
        return self.__path

    @property
    def close_on_exec(self) -> int:
        return self._close_on_exec

    @close_on_exec.setter
    def close_on_exec(self, value: int) -> None:
        self._close_on_exec = value
