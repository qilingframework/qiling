#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os
from typing import AnyStr, Optional

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
        self.__closed = False

        # information for syscall mmap
        self._is_map_shared = False
        self._mapped_offset = -1
        self.close_on_exec = False

    @classmethod
    def open(cls, path: AnyStr, flags: int, mode: int, dir_fd: Optional[int] = None):
        mode &= 0x7fffffff

        try:
            fd = os.open(path, flags, mode, dir_fd=dir_fd)
        except OSError as e:
            raise QlSyscallError(e.errno, e.args[1] + ' : ' + e.filename)

        return cls(path, fd)

    def read(self, read_len: int) -> bytes:
        return os.read(self.__fd, read_len)

    def write(self, write_buf: bytes) -> int:
        return os.write(self.__fd, write_buf)

    def fileno(self) -> int:
        return self.__fd

    def seek(self, lseek_offset: int, lseek_origin: int = os.SEEK_SET) -> int:
        return self.lseek(lseek_offset, lseek_origin)

    def lseek(self, lseek_offset: int, lseek_origin: int = os.SEEK_SET) -> int:
        return os.lseek(self.__fd, lseek_offset, lseek_origin)

    def close(self) -> None:
        os.close(self.__fd)

        self.__closed = True

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
    def closed(self) -> bool:
        return self.__closed


class PersistentQlFile(ql_file):
    """A persistent variation of the ql_file class, which silently drops
    attempts to close its udnerlying file. This is useful when using host
    environment resources, which should not be closed when their wrapping
    ql_file gets closed.

    For example, stdout and stderr might be closed by the emulated program
    by calling POSIX dup2 or dup3 system calls, and then replaced by another
    file or socket. this class prevents the emulated program from closing
    shared resources on the hosting system.
    """

    def close(self):
        pass
