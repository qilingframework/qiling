#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#
import os

from typing import TextIO

from qiling.os.posix import stat

class SimpleStringBuffer(TextIO):
    """Simple FIFO pipe.
    """

    def __init__(self):
        self.buff = bytearray()

    def read(self, n: int = -1) -> bytes:
        if n == -1:
            ret = self.buff
            rem = bytearray()
        else:
            ret = self.buff[:n]
            rem = self.buff[n:]

        self.buff = rem

        return bytes(ret)

    def readline(self, limit: int = -1) -> bytes:
        ret = bytearray()

        while not (ret.endswith(b'\n') or len(ret) == limit):
            ret.extend(self.read(1))

        return bytes(ret)

    def write(self, s: bytes) -> int:
        self.buff.extend(s)

        return len(s)

    def flush(self) -> None:
        pass

    def writable(self) -> bool:
        return True

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

class SimpleStreamBase:
    def __init__(self, fd: int, *args):
        super().__init__(*args)

        self.__fd = fd
        self.__closed = False
    
    def close(self) -> None:
        self.__closed = True
    
    def closed(self) -> bool:
        return self.__closed

    def fileno(self) -> int:
        return self.__fd

    def fstat(self):
        return stat.Fstat(self.fileno())

class SimpleInStream(SimpleStreamBase, SimpleStringBuffer):
    """Simple input stream. May be used to mock stdin.
    """

    pass

class SimpleOutStream(SimpleStreamBase, SimpleStringBuffer):
    """Simple output stream. May be used to mock stdout or stderr.
    """

    pass

class NullOutStream(SimpleStreamBase):
    """Null out-stream, may be used to disregard process output.
    """

    def write(self, s: bytes) -> int:
        return len(s)

    def flush(self) -> None:
        pass

    def writable(self) -> bool:
        return True

class SimpleBufferedStream(TextIO):
    """Simple buffered IO.
    """

    def __init__(self):
        self.buff = bytearray()
        self.cur = 0

    def lseek(self, offset: int, origin: int) -> int:
        if origin == 0: # SEEK_SET
            base = 0
        elif origin == 1: # SEEK_CUR
            base = self.cur
        else: # SEEK_END
            base = len(self.buff) - 1

        if base + offset >= len(self.buff):
            self.cur = base + offset - 1
        else:
            self.cur = base + offset

        return self.cur

    def seek(self, offset: int, origin: int) -> int:
        return self.lseek(offset, origin)
    
    def tell(self) -> int:
        return self.cur

    def read(self, n: int = -1) -> bytes:
        if n == -1:
            ret = self.buff
        else:
            ret = self.buff[self.cur:self.cur + n]

            if self.cur + n >= len(self.buff) - 1:
                self.cur = len(self.buff)
            else:
                self.cur = self.cur + n

        return bytes(ret)

    def readline(self, limit: int = -1) -> bytes:
        ret = bytearray()

        while not (ret.endswith(b'\n') or len(ret) == limit):
            ret.extend(self.read(1))

        return bytes(ret)

    def write(self, s: bytes) -> int:
        self.buff.extend(s)

        return len(s)

    def flush(self) -> None:
        pass

    def writable(self) -> bool:
        return True

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True