import ctypes
import struct
import unittest

from qiling.os.posix.syscall.stat import (
    LinuxARMEBStat,
    LinuxARMStat,
    LinuxARMStat64,
    __common_pack_stat_struct as common_pack_stat_struct,
)


class ARMStatTimestampUnitTest(unittest.TestCase):
    def _check_struct(self, stat_type, byteorder):
        timestamps = {
            "st_atime_ns": (1_791_143_806_588_454_438, 588_454_438),
            "st_mtime_ns": (1_791_143_806_592_454_430, 592_454_430),
            "st_ctime_ns": (1_791_143_806_592_454_430, 592_454_430),
        }
        seconds = {
            "st_atime": 1_791_143_806,
            "st_mtime": 1_791_143_806,
            "st_ctime": 1_791_143_806,
        }
        info = {field: 0 for field, _ in stat_type._fields_}
        info.update(seconds)
        info["st_size"] = 29
        for field, (epoch_ns, _) in timestamps.items():
            info[field] = epoch_ns

        stat = stat_type()
        packed = common_pack_stat_struct(stat, info)

        self.assertEqual(len(packed), ctypes.sizeof(stat_type))
        self.assertEqual(stat.st_size, 29)
        for field, expected in seconds.items():
            self.assertEqual(getattr(stat, field), expected)
        for field, (_, expected) in timestamps.items():
            with self.subTest(field=field):
                self.assertEqual(getattr(stat, field), expected)
                offset = getattr(stat_type, field).offset
                actual = struct.unpack_from(byteorder + "I", packed, offset)[0]
                self.assertEqual(actual, expected)

    def test_little_endian_arm_stat_timestamps_use_subsecond_units(self):
        self._check_struct(LinuxARMStat, "<")

    def test_big_endian_arm_stat_timestamps_use_subsecond_units(self):
        self._check_struct(LinuxARMEBStat, ">")

    def test_little_endian_arm_stat64_timestamps_use_subsecond_units(self):
        self._check_struct(LinuxARMStat64, "<")
