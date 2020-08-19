from .mapper import QlFsMappedObject

# Open a file as a Disk
#     host_path: The file path on the host machine.
#     drive_path: The drive path on the emulated system. e.g. /dev/sda \\.\PHYSICALDRIVE0 0x80
# 
# Note: CHS and LBA support is very limited since a raw file doesn't contain enough information.
# See: https://en.wikipedia.org/wiki/Cylinder-head-sector
#      https://en.wikipedia.org/wiki/Logical_block_addressing
class QlDisk(QlFsMappedObject):

    def __init__(self, host_path, drive_path, n_heads=1, n_sectors=1, sector_size=512):
        self._host_path = host_path
        self._drive_path = drive_path
        self._f = open(host_path, "rb+")
        self._n_heads = n_heads
        self._n_sectors = n_sectors
        self._sector_size = sector_size

    def __del__(self):
        if not self.f.closed:
            self.f.close()

    @property
    def n_heads(self):
        return self._n_heads

    @property
    def n_sectors(self):
        return self._n_sectors

    @property
    def sector_size(self):
        return self._sector_size

    @property
    def host_path(self):
        return self._host_path
    
    @property
    def drive_path(self):
        return self._drive_path
    
    @property
    def f(self):
        return self._f

    # Methods from FsMappedObject
    def read(self, l):
        return self.f.read(l)
    
    def write(self, bs):
        return self.f.write(bs)

    def lseek(self, offset, origin):
        return self.f.seek(offset, origin)
    
    def close(self):
        return self.f.close()
    
    # Methods for QlDisk
    def lba(self, cylinder, head, sector):
        return (cylinder * self.n_heads + head) * self._n_sectors + sector - 1
    
    def read_sectors(self, lba, cnt):
        self.lseek(self.sector_size * lba, 0)
        return self.read(self.sector_size*cnt)
    
    def read_chs(self, cylinder, head, sector, cnt):
        return self.read_sectors(self.lba(cylinder, head, sector), cnt)

    def write_sectors(self, lba, cnt, buffer):
        if len(buffer) > self.sector_size * cnt:
            buffer = buffer[:self.sector_size*cnt]
        self.lseek(self.sector_size * lba, 0)
        return self.write(buffer)
    
    def write_chs(self, cylinder, head, sector, cnt, buffer):
        return self.write_sectors(self.lba(cylinder, head, sector), cnt, buffer)