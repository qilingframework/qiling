#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 


import sys,unittest
sys.path.append("..")
from qiling import *
from qiling.exception import *

class Test_UEFI(unittest.TestCase):
    def test_x8664_uefi(self):
        ql = Qiling(["../examples/rootfs/x8664_efi/bin/TcgPlatformSetupPolicy"], "../examples/rootfs/x8664_efi", env="rootfs/x8664_efi/rom2_nvar.pickel")
        ql.run()

if __name__ == "__main__":
    unittest.main()
