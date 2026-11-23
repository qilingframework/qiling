import os
import tempfile
import unittest
from types import SimpleNamespace

from qiling.const import QL_ARCH
from qiling.os.filestruct import ql_file
from qiling.os.posix.const import EBADF
from qiling.os.posix.syscall.unistd import ql_syscall_pread64


class _Memory:
    def __init__(self):
        self.write_calls = []

    @staticmethod
    def is_mapped(_address, _length):
        return True

    def write(self, address, data):
        self.write_calls.append((address, bytes(data)))


class _ReadableFile:
    def tell(self):
        return 9

    @staticmethod
    def seek(_position):
        pass

    @staticmethod
    def read(_length):
        return b"R"


class _Qiling:
    def __init__(self, file_obj):
        fds = [None] * 8
        fds[3] = file_obj
        self.os = SimpleNamespace(fd=fds)
        self.mem = _Memory()
        self.arch = SimpleNamespace(type=QL_ARCH.RISCV64)


class Pread64ErrnoTests(unittest.TestCase):
    def test_write_only_descriptor_returns_ebadf(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "probe.bin")
            with open(path, "wb") as file:
                file.write(b"X")

            file_obj = ql_file.open(path, os.O_WRONLY, 0)
            ql = _Qiling(file_obj)
            try:
                result = ql_syscall_pread64(ql, 3, 0x2000, 1, 0)
            finally:
                file_obj.close()

            self.assertEqual(result, -EBADF, "host EBADF must remain guest -EBADF")
            self.assertEqual(ql.mem.write_calls, [], "failed pread must not copy to guest memory")

    def test_readable_descriptor_control_copies_data(self):
        ql = _Qiling(_ReadableFile())

        result = ql_syscall_pread64(ql, 3, 0x2000, 1, 2)

        self.assertEqual(result, 1, "readable descriptor must report the byte count")
        self.assertEqual(ql.mem.write_calls, [(0x2000, b"R")], "successful pread must copy its data")


if __name__ == "__main__":
    unittest.main()
