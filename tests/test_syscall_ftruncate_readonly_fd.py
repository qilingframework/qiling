import errno
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from qiling.os.filestruct import ql_file
from qiling.os.posix.const import NR_OPEN
from qiling.os.posix.syscall.unistd import ql_syscall_ftruncate


DATA = b"RV64-FTRUNCATE-CONTROL\n"


def make_ql(file_obj=None, fd=3):
    descriptors = [None] * NR_OPEN
    if file_obj is not None:
        descriptors[fd] = file_obj
    return SimpleNamespace(
        os=SimpleNamespace(fd=descriptors),
        log=SimpleNamespace(debug=Mock()),
    )


class TestFtruncateReadonlyFd(unittest.TestCase):
    def test_readonly_descriptor_fails_without_changing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "target.bin"
            path.write_bytes(DATA)
            file_obj = ql_file.open(str(path), os.O_RDONLY, 0)
            try:
                result = ql_syscall_ftruncate(make_ql(file_obj), 3, 0)
                self.assertIn(result, (-errno.EBADF, -errno.EINVAL))
                self.assertEqual(path.read_bytes(), DATA)
            finally:
                file_obj.close()

    def test_writable_descriptor_truncates_and_extends(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "target.bin"
            path.write_bytes(DATA)
            file_obj = ql_file.open(str(path), os.O_RDWR, 0)
            try:
                ql = make_ql(file_obj)
                self.assertEqual(ql_syscall_ftruncate(ql, 3, 5), 0)
                self.assertEqual(path.read_bytes(), DATA[:5])
                self.assertEqual(ql_syscall_ftruncate(ql, 3, 31), 0)
                self.assertEqual(path.read_bytes(), DATA[:5] + bytes(26))
            finally:
                file_obj.close()

    def test_negative_length_returns_einval_without_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "target.bin"
            path.write_bytes(DATA)
            file_obj = ql_file.open(str(path), os.O_RDWR, 0)
            try:
                result = ql_syscall_ftruncate(make_ql(file_obj), 3, -1)
                self.assertEqual(result, -errno.EINVAL)
                self.assertEqual(path.read_bytes(), DATA)
            finally:
                file_obj.close()

    def test_invalid_guest_fd_returns_ebadf(self):
        self.assertEqual(ql_syscall_ftruncate(make_ql(), 3, 0), -errno.EBADF)

    def test_file_object_without_host_descriptor_returns_einval(self):
        self.assertEqual(ql_syscall_ftruncate(make_ql(object()), 3, 0), -errno.EINVAL)


if __name__ == "__main__":
    unittest.main()
