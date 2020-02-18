#!/usr/bin/env python3

import sys,unittest
sys.path.append("..")
from qiling import *

class dbgTest(unittest.TestCase):
    def test_gdb_x86(self):
        ql = Qiling(["./examples/rootfs/x86_windows/bin/x86_hello.exe"], "./examples/rootfs/x86_windows/bin")
        ql.gdb = ":9999"
        ql.run()
        del ql

    def test_gdb_x8664(self):
        ql = Qiling(["./examples/rootfs/x8664_windows/bin/x8664_hello.exe"], "./examples/rootfs/x8664_windows/bin")
        ql.gdb = ":9999"
        ql.run()
        del ql


if __name__ == "__main__":
    unittest.main()
