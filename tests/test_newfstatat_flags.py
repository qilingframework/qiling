#!/usr/bin/env python3

import unittest
from unittest.mock import Mock, patch

from qiling.os.posix.const import (
    AT_EMPTY_PATH,
    AT_NO_AUTOMOUNT,
    AT_STATX_DONT_SYNC,
    AT_STATX_FORCE_SYNC,
    AT_STATX_SYNC_TYPE,
    AT_SYMLINK_NOFOLLOW,
    EINVAL,
)
from qiling.os.posix.syscall import stat as stat_syscall


class TestNewfstatatFlags(unittest.TestCase):
    def setUp(self):
        self.ql = Mock()

    def test_unknown_flags_return_einval_before_path_or_copyout(self):
        with patch.object(stat_syscall, "transform_path") as transform_path, \
                patch.object(stat_syscall, "Stat") as stat, \
                patch.object(stat_syscall, "pack_stat_struct") as pack_stat:
            result = stat_syscall.ql_syscall_newfstatat(
                self.ql, -100, 0x1000, 0x2000, 0x40000000
            )

        self.assertEqual(-EINVAL, result, "unknown flags should return -EINVAL")
        self.assertFalse(transform_path.called, "invalid flags must fail before path lookup")
        self.assertFalse(stat.called, "invalid flags must fail before host stat")
        self.assertFalse(pack_stat.called, "invalid flags must fail before serialization")
        self.assertFalse(self.ql.mem.write.called, "invalid flags must not copy out stat data")

    def test_supported_flags_and_32bit_truncation(self):
        flags_cases = (
            (0, 0),
            (AT_SYMLINK_NOFOLLOW, AT_SYMLINK_NOFOLLOW),
            (AT_NO_AUTOMOUNT, AT_NO_AUTOMOUNT),
            (AT_EMPTY_PATH, AT_EMPTY_PATH),
            (AT_STATX_FORCE_SYNC, AT_STATX_FORCE_SYNC),
            (AT_STATX_DONT_SYNC, AT_STATX_DONT_SYNC),
            (AT_STATX_SYNC_TYPE, AT_STATX_SYNC_TYPE),
            (0x100000000, 0),
        )

        for input_flags, flags in flags_cases:
            with self.subTest(input_flags=input_flags):
                self.ql.reset_mock()
                with patch.object(
                    stat_syscall, "transform_path", return_value=(None, "/file")
                ) as transform_path, \
                        patch.object(stat_syscall, "Stat", return_value=Mock()), \
                        patch.object(stat_syscall, "pack_stat_struct", return_value=b"stat"):
                    result = stat_syscall.ql_syscall_newfstatat(
                        self.ql, -100, 0x1000, 0x2000, input_flags
                    )

                self.assertEqual(0, result, "supported flags should reach stat handling")
                self.assertEqual(
                    1,
                    transform_path.call_count,
                    "supported flags should perform one path lookup",
                )
                self.assertEqual(
                    ((self.ql, -100, 0x1000, flags), {}),
                    transform_path.call_args,
                    "path lookup should receive the 32-bit syscall flags",
                )
                self.assertEqual(
                    ((0x2000, b"stat"), {}),
                    self.ql.mem.write.call_args,
                    "supported flags should preserve successful copyout",
                )


if __name__ == "__main__":
    unittest.main()
