#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 


import sys, unittest
sys.path.append("..")
from qiling import *
from qiling.exception import *

class MACHOTest(unittest.TestCase):
    def test_macho_macos_x8664(self):
        ql = Qiling(["../examples/rootfs/x8664_macos/bin/x8664_hello_usercorn"], "../examples/rootfs/x8664_macos", output = "disasm")
        ql.console = False
        ql.run()

if __name__ == "__main__":
    unittest.main()
