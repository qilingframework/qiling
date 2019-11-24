#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import sys,unittest
sys.path.append("..")
from qiling import *
from qiling.exception import *

class ELFTest(unittest.TestCase):
    def test_elf_linux_x8664(self):
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/tester","1234test", "12345678", "bin/x8664_hello"],  "../examples/rootfs/x8664_linux", output="debug")
        ql.run()
        
if __name__ == "__main__":
    unittest.main()