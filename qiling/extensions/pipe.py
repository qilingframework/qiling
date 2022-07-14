#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#
import io
import os
from typing import TextIO

from qiling.os.posix import stat

class SimpleStringBuffer(io.BytesIO):
    """Simple FIFO pipe.
    """

    def __init__(self):
        super().__init__()
    
    # Compatible with old implementation
    def seek(self, offset: int, origin: int = 0) -> int:
        # Imitate os.lseek
        raise OSError("Illega Seek")

    def seekable(self) -> bool:
        return False

    def write(self, buf: bytes) -> int:
        # For the FIFO stream, the write doesn't change pos.
        pos = super().tell()
        super().seek(0, os.SEEK_END)
        ret = super().write(buf)
        super().seek(pos)
        return ret
    
    # Compatible with previous TextIO
    @property
    def name(self):
        return None

class SimpleStreamBase:
    def __init__(self, fd: int):
        super().__init__()

        self.__fd = fd
        self.__closed = False
    
    def close(self) -> None:
        self.__closed = True
    
    @property
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

class SimpleBufferedStream(io.BytesIO):
    """Simple buffered IO.
    """

    def __init__(self):
        super.__init__()