#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from qiling.const import QL_OS
from qiling.os.posix.const import EINVAL
from qiling.os.posix.syscall.time import ql_syscall_clock_nanosleep


class TestClockNanosleepClockId(unittest.TestCase):
    def make_ql(self, os_type=QL_OS.LINUX):
        return SimpleNamespace(os=SimpleNamespace(type=os_type))

    @patch('qiling.os.posix.syscall.time.__sleep_common', return_value=0)
    def test_rejects_invalid_positive_static_clock_ids(self, sleep):
        ql = self.make_ql()

        for clockid in (10, 12, 999, 0x1000003e7):
            with self.subTest(clockid=clockid):
                self.assertEqual(ql_syscall_clock_nanosleep(ql, clockid, 0, 0, 0), -EINVAL)

        sleep.assert_not_called()

    @patch('qiling.os.posix.syscall.time.__sleep_common', return_value=0)
    def test_known_static_ids_keep_the_existing_sleep_path(self, sleep):
        ql = self.make_ql()

        for clockid in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11):
            with self.subTest(clockid=clockid):
                self.assertEqual(ql_syscall_clock_nanosleep(ql, clockid, 0, 0, 0), 0)

        self.assertEqual(sleep.call_count, 11)

    @patch('qiling.os.posix.syscall.time.__sleep_common', return_value=0)
    def test_signed_and_wide_arguments_are_normalized_as_clockid_t(self, sleep):
        ql = self.make_ql()

        for clockid in (-1, 0xffffffff, 0xffffffffffffffff, 0x100000001):
            with self.subTest(clockid=clockid):
                self.assertEqual(ql_syscall_clock_nanosleep(ql, clockid, 0, 0, 0), 0)

        self.assertEqual(sleep.call_count, 4)

    @patch('qiling.os.posix.syscall.time.__sleep_common', return_value=0)
    def test_other_posix_os_keeps_the_existing_sleep_path(self, sleep):
        ql = self.make_ql(QL_OS.FREEBSD)

        self.assertEqual(ql_syscall_clock_nanosleep(ql, 999, 0, 0, 0), 0)
        sleep.assert_called_once_with(ql, 0, 0)


if __name__ == '__main__':
    unittest.main()
