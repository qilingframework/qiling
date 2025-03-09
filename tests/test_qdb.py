#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
import unittest

sys.path.append("..")
from qiling import Qiling
from qiling.const import QL_VERBOSE


class DebuggerTest(unittest.TestCase):

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


if __name__ == '__main__':
    unittest.main()
