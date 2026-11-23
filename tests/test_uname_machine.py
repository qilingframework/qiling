#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from qiling.const import QL_ARCH, QL_ENDIAN, QL_OS
from qiling.os.posix.syscall.utsname import ql_syscall_uname


class UnameMachineTest(unittest.TestCase):
    def invoke(self, os_type, arch_type, endian=QL_ENDIAN.EL):
        ql = SimpleNamespace(
            arch=SimpleNamespace(type=arch_type, endian=endian),
            os=SimpleNamespace(type=os_type),
            mem=Mock(),
        )
        self.assertEqual(0, ql_syscall_uname(ql, 0x1000))
        writes = [call.args for call in ql.mem.write.call_args_list]
        self.assertEqual([0x1000 + i * 65 for i in range(6)], [addr for addr, _ in writes])
        self.assertEqual([65] * 6, [len(data) for _, data in writes])
        return [data for _, data in writes]

    def test_linux_rv64_reports_riscv64(self):
        fields = self.invoke(QL_OS.LINUX, QL_ARCH.RISCV64)
        self.assertEqual(b'riscv64'.ljust(65, b'\x00'), fields[4])

    def test_other_linux_profiles_keep_existing_machine_value(self):
        for os_type, arch_type in (
            (QL_OS.LINUX, QL_ARCH.RISCV),
            (QL_OS.LINUX, QL_ARCH.X8664),
        ):
            with self.subTest(os=os_type.name, arch=arch_type.name):
                fields = self.invoke(os_type, arch_type)
                self.assertEqual(b'ql_processor'.ljust(65, b'\x00'), fields[4])

    def test_non_linux_machine_keeps_profile_value(self):
        fields = self.invoke(QL_OS.FREEBSD, QL_ARCH.RISCV64)
        self.assertEqual(b'ql_processor' + bytes(53), fields[4])

    def test_linux_riscv_update_preserves_other_uts_fields(self):
        fields = self.invoke(QL_OS.LINUX, QL_ARCH.RISCV64)
        expected = tuple(
            value.ljust(65, b'\x00')
            for value in (b'QilingOS', b'ql_vm', b'99.0-RELEASE', b'QilingOS 99.0-RELEASE r1', b'')
        )
        self.assertEqual(expected, tuple(fields[:4] + fields[5:]))


if __name__ == '__main__':
    unittest.main()
