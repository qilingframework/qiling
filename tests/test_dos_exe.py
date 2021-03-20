#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys, unittest
sys.path.append('..')

from qiling import Qiling

class DOSTest(unittest.TestCase):

    def test_dos_8086_hello(self):
        ql = Qiling(["../examples/rootfs/8086/dos/ARKA.DOS_EXE"], "../examples/rootfs/8086/dos")
        ql.run()
        del ql

if __name__ == "__main__":
    unittest.main()
