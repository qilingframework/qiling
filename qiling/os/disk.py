#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import AnyStr, Optional, Union
from .mapper import QlFsMappedObject

ReadableBuffer = Union[bytes, bytearray, memoryview]


# Open a file as a Disk
#     host_path: The file path on the host machine.
#     drive_path: The drive path on the emulated system. e.g. /dev/sda \\.\PHYSICALDRIVE0 0x80
#
# Note: CHS and LBA support is very limited since a raw file doesn't contain enough information.
#       We simply assume that it is a disk with 1 head, 1 cylinder and (filesize/512) sectors.
#
# See: https://en.wikipedia.org/wiki/Cylinder-head-sector
#      https://en.wikipedia.org/wiki/Logical_block_addressing
#      http://www.uruk.org/orig-grub/PC_partitioning.txt

class QlDisk(QlFsMappedObject):

    # 512 bytes/sector
    # 63 sectors/track
    # 255 heads (tracks/cylinder)
    # 1024 cylinders

    def __init__(self, host_path: AnyStr, drive_path, n_cylinders: int = 1, n_heads: int = 1, sector_size: int = 512):
        self._drive_path = drive_path
        self._fp = open(host_path, "rb+")
        self._n_heads = n_heads
        self._n_cylinders = n_cylinders
        self._sector_size = sector_size
        self.lseek(0, 2)
        self._filesize = self.tell()
        self._n_sectors = (self._filesize - 1) // self.sector_size + 1

    def __del__(self):
        if not self.fp.closed:
            self.fp.close()

    @property
    def filesize(self):
        return self._filesize

    @property
    def n_heads(self):
        return self._n_heads

    @property
    def n_sectors(self):
        return self._n_sectors

    @property
    def n_cylinders(self):
        return self._n_cylinders

    @property
    def sector_size(self):
        return self._sector_size

    @property
    def fp(self):
        return self._fp

    # Methods from FsMappedObject
    def read(self, size: Optional[int]) -> bytes:
        return self.fp.read(size)

    def write(self, buffer: ReadableBuffer) -> int:
        return self.fp.write(buffer)

    def lseek(self, offset: int, origin: int) -> int:
        return self.fp.seek(offset, origin)

    def tell(self) -> int:
        return self.fp.tell()

    def close(self) -> None:
        self.fp.close()

    # Methods for QlDisk
    def lba(self, cylinder: int, head: int, sector: int) -> int:
        return (cylinder * self.n_heads + head) * self._n_sectors + sector - 1

    def read_sectors(self, lba: int, cnt: int) -> bytes:
        self.lseek(self.sector_size * lba, 0)

        return self.read(self.sector_size * cnt)

    def read_chs(self, cylinder: int, head: int, sector: int, cnt: int) -> bytes:
        return self.read_sectors(self.lba(cylinder, head, sector), cnt)

    def write_sectors(self, lba: int, cnt: int, buffer: ReadableBuffer) -> int:
        buffer = memoryview(buffer)
        self.lseek(self.sector_size * lba, 0)

        return self.write(buffer[:self.sector_size * cnt])

    def write_chs(self, cylinder: int, head: int, sector: int, cnt: int, buffer: ReadableBuffer):
        return self.write_sectors(self.lba(cylinder, head, sector), cnt, buffer)
