#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


import sys, unittest
sys.path.append("..")

from qiling.core import Qiling
from qiling.const import QL_VERBOSE

class MCUTest(unittest.TestCase):
    def test_mcu_led_hex_stm32f411(self):
        ql = Qiling(["../examples/rootfs/stm32f411/hex/rand_blink.hex"],                    
                    archtype="cortex_m", profile="stm32f411", verbose=QL_VERBOSE.DISASM)
        ql.run(count=10000)

        del ql

if __name__ == "__main__":
    unittest.main()
