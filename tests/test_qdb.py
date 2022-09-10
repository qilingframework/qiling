#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys, unittest

sys.path.append("..")
from qiling import Qiling

class DebuggerTest(unittest.TestCase):

    def test_qdb_mips32el_hello(self):
        rootfs = "../examples/rootfs/mips32el_linux"
        path = rootfs + "/bin/mips32el_hello"

        ql = Qiling([path], rootfs)
        ql.debugger = "qdb::rr:qdb_scripts/mips32el.qdb"
        ql.run()
        del ql

    def test_qdb_arm_hello(self):
        rootfs = "../examples/rootfs/arm_linux"
        path = rootfs + "/bin/arm_hello"

        ql = Qiling([path], rootfs)
        ql.debugger = "qdb::rr:qdb_scripts/arm.qdb"
        ql.run()
        del ql

    def test_qdb_x86_hello(self):
        rootfs = "../examples/rootfs/x86_linux"
        path = rootfs + "/bin/x86_hello"

        ql = Qiling([path], rootfs)
        ql.debugger = "qdb::rr:qdb_scripts/x86.qdb"
        ql.run()
        del ql

if __name__ == "__main__":
    unittest.main()
