from types import SimpleNamespace
import unittest

from qiling.os.filestruct import ql_file
from qiling.os.posix.syscall.mman import ql_syscall_munmap


class MappedFile(ql_file):
    def __init__(self, size, offset):
        super().__init__('/tmp/mapped.bin', -1)
        self.size = size
        self._mapped_offset = offset
        self._is_map_shared = True
        self.writeback = None
        self.seeked = None
        self.read_lengths = []

    def fstat(self):
        return SimpleNamespace(st_size=self.size)

    def lseek(self, offset, origin=0):
        self.seeked = offset

    def write(self, data):
        self.writeback = data
        return len(data)


def run_munmap(size, offset, length):
    file = MappedFile(size, offset)

    def read(_address, count):
        file.read_lengths.append(count)
        return b'Z' * count

    mem = SimpleNamespace(
        get_mapinfo=lambda: [(0x1000, 0x2000, 0, '[mmap] mapped.bin', 0)],
        read=read,
        align=lambda address: address & ~0xfff,
        align_up=lambda address: (address + 0xfff) & ~0xfff,
        unmap=lambda address, count: None,
    )
    ql = SimpleNamespace(
        mem=mem,
        os=SimpleNamespace(fd=[file]),
        log=SimpleNamespace(debug=lambda message: None),
    )

    assert ql_syscall_munmap(ql, 0x1000, length) == 0
    return file


class MunmapSharedEofTests(unittest.TestCase):
    def test_shared_writeback_stops_at_eof(self):
        file = run_munmap(size=100, offset=0, length=4096)

        self.assertEqual(file.seeked, 0)
        self.assertEqual(file.writeback, b'Z' * 100)

    def test_shared_writeback_respects_mapping_file_offset(self):
        file = run_munmap(size=100, offset=50, length=4096)

        self.assertEqual(file.seeked, 50)
        self.assertEqual(file.writeback, b'Z' * 50)

    def test_shared_mapping_starting_at_eof_does_not_write(self):
        file = run_munmap(size=100, offset=100, length=4096)

        self.assertIsNone(file.seeked)
        self.assertIsNone(file.writeback)

    def test_overlength_munmap_reads_only_mapped_bytes(self):
        file = run_munmap(size=8192, offset=0, length=8192)

        self.assertEqual(file.read_lengths, [4096])
        self.assertEqual(file.writeback, b'Z' * 4096)
