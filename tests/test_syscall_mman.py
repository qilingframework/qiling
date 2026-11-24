import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from qiling.const import QL_OS
from qiling.os.posix.const import ENOMEM
from qiling.os.posix.syscall.mman import ql_syscall_mprotect


class MprotectRangeOverflowTests(unittest.TestCase):
    @staticmethod
    def _ql(os_type=QL_OS.LINUX, max_mem_addr=(1 << 64) - 1):
        memory = SimpleNamespace(
            pagesize=4096,
            max_mem_addr=max_mem_addr,
            protect=Mock(),
        )
        return SimpleNamespace(os=SimpleNamespace(type=os_type), mem=memory)

    def test_linux_overflow_returns_enomem_before_protection(self):
        ql = self._ql()
        result = ql_syscall_mprotect(ql, 0x1000, (1 << 64) - 1, 1)
        self.assertEqual(result, -ENOMEM)
        ql.mem.protect.assert_not_called()

    def test_one_page_control_reaches_memory_manager(self):
        ql = self._ql()
        result = ql_syscall_mprotect(ql, 0x1000, 4096, 1)
        self.assertEqual(result, 0)
        ql.mem.protect.assert_called_once_with(0x1000, 4096, 1)

    def test_range_including_last_guest_address_is_not_overflow(self):
        ql = self._ql()
        start = ql.mem.max_mem_addr + 1 - ql.mem.pagesize
        result = ql_syscall_mprotect(ql, start, ql.mem.pagesize, 1)
        self.assertEqual(result, 0)
        ql.mem.protect.assert_called_once_with(start, ql.mem.pagesize, 1)

    def test_start_beyond_address_space_returns_enomem(self):
        ql = self._ql()
        start = ql.mem.max_mem_addr + 1
        result = ql_syscall_mprotect(ql, start, ql.mem.pagesize, 1)
        self.assertEqual(result, -ENOMEM)
        ql.mem.protect.assert_not_called()

    def test_range_uses_guest_address_width(self):
        ql = self._ql(max_mem_addr=(1 << 32) - 1)
        result = ql_syscall_mprotect(ql, 0x1000, (1 << 32) - 1, 1)
        self.assertEqual(result, -ENOMEM)
        ql.mem.protect.assert_not_called()

    def test_zero_length_keeps_existing_path(self):
        ql = self._ql()
        result = ql_syscall_mprotect(ql, 0x1000, 0, 1)
        self.assertEqual(result, 0)
        ql.mem.protect.assert_called_once_with(0x1000, 0, 1)

    def test_non_linux_personality_keeps_existing_path(self):
        ql = self._ql(QL_OS.FREEBSD)
        length = (1 << 64) - 1
        result = ql_syscall_mprotect(ql, 0x1000, length, 1)
        self.assertEqual(result, 0)
        ql.mem.protect.assert_called_once_with(0x1000, length, 1)


if __name__ == "__main__":
    unittest.main()
