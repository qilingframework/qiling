#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
import unittest
from unittest.mock import patch

sys.path.append("..")
from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
from qiling.debugger.qdb.qdb import QlQdb


class DebuggerTest(unittest.TestCase):

    def test_qdb_linux_shellcode_entry_point(self):
        for archtype in (QL_ARCH.X86, QL_ARCH.X8664):
            with self.subTest(archtype=archtype):
                code = b'\x90\x90'
                ql = Qiling(code=code, archtype=archtype, ostype=QL_OS.LINUX,
                            verbose=QL_VERBOSE.OFF, console=False)

                self.assertIsNone(ql.entry_point)

                with patch.object(QlQdb, 'cmdloop') as cmdloop, patch.object(QlQdb, 'do_context'):
                    debugger = QlQdb(ql)

                self.assertEqual(ql.loader.entry_point, ql.loader.load_address)
                self.assertEqual(ql.loader.entry_point, ql.os.entry_point)
                self.assertEqual(ql.mem.read(ql.loader.entry_point, len(code)), code)
                self.assertEqual(debugger.cur_addr, ql.loader.entry_point)
                cmdloop.assert_called_once_with()

    def __test_common(self, vpath: str, rootfs: str, script: str) -> None:
        """Load a common setup for all test cases.
        """

        ql = Qiling([f'{rootfs}{vpath}'], rootfs, verbose=QL_VERBOSE.DEBUG)
        ql.debugger = f'qdb::rr:{script}'

        try:
            ql.run()
        except SystemExit as ex:
            self.assertEqual(ex.code, 0)

    def test_qdb_mips32el_hello(self):
        self.__test_common(
            r'/bin/mips32el_hello',
            r'../examples/rootfs/mips32el_linux',
            r'qdb_scripts/mips32el.qdb'
        )

    def test_qdb_arm_hello(self):
        self.__test_common(
            r'/bin/arm_hello',
            r'../examples/rootfs/arm_linux',
            r'qdb_scripts/arm.qdb'
        )

    def test_qdb_arm_hello_static(self):
        self.__test_common(
            r'/bin/arm_hello_static',
            r'../examples/rootfs/arm_linux',
            r'qdb_scripts/arm_static.qdb'
        )

    def test_qdb_x86_hello(self):
        self.__test_common(
            r'/bin/x86_hello',
            r'../examples/rootfs/x86_linux',
            r'qdb_scripts/x86.qdb'
        )

    def test_qdb_riscv32_hello(self):
        self.__test_common(
            r'/bin/hello',
            r'../examples/rootfs/riscv32_linux',
            r'qdb_scripts/riscv32.qdb'
        )

    def test_qdb_riscv64_hello(self):
        self.__test_common(
            r'/bin/hello',
            r'../examples/rootfs/riscv64_linux',
            r'qdb_scripts/riscv64.qdb'
        )


if __name__ == '__main__':
    unittest.main()
