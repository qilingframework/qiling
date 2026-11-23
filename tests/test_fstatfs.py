import unittest
from unittest.mock import Mock

from qiling.os.posix.const import EBADF, NR_OPEN
from qiling.os.posix.syscall.stat import ql_syscall_fstatfs


class FstatfsTest(unittest.TestCase):
    def setUp(self):
        self.ql = Mock()
        self.ql.os.fd = [None] * NR_OPEN
        self.ql.os.fd[0] = object()

    def test_invalid_fd_returns_ebadf_without_copyout(self):
        for fd in (-1, 3, NR_OPEN, 0xFFFFFFFFFFFFFFFF):
            with self.subTest(fd=fd):
                self.assertEqual(
                    -EBADF,
                    ql_syscall_fstatfs(self.ql, fd, 0x1000),
                )
                self.ql.mem.write.assert_not_called()

    def test_valid_fd_preserves_existing_copyout(self):
        self.assertEqual(0, ql_syscall_fstatfs(self.ql, 0, 0x1000))
        self.ql.mem.write.assert_called_once_with(0x1000, b"0" * (12 * 8))

    def test_riscv64_ignores_bits_above_the_32_bit_fd(self):
        self.assertEqual(0, ql_syscall_fstatfs(self.ql, 0x100000000, 0x1000))
        self.ql.mem.write.assert_called_once_with(0x1000, b"0" * (12 * 8))
