#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 


import sys,unittest
sys.path.append("..")
from qiling import *
from qiling.exception import *

class PETest(unittest.TestCase):
    def test_pe_win_x8664(self):
        ql = Qiling(["../examples/rootfs/x8664_reactos/bin/x8664_hello.exe"], "..\\examples\\rootfs\\x8664_windows", output = "debug")
        ql.run()


    def test_pe_win_x86(self):
        ql = Qiling(["../examples/rootfs/x86_reactos/bin/x86_hello.exe"], "../examples/rootfs/x86_windows", output = "debug")
        ql.run()


if __name__ == "__main__":
    unittest.main()