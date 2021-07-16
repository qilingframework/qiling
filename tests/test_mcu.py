#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


import sys, unittest
sys.path.append("..")

from qiling.core import Qiling

class MCUTest(unittest.TestCase):
    def test_mcu_led_hex_stm32f411(self):
        ql = Qiling(["../examples/rootfs/stm32f411/hex/rand_blink.hex"],                    
                    archtype="cortex_m",
                    engine=True)

        ql.engine.setup()
        ql.engine.flash()        
        ql.engine.start()

        del ql

if __name__ == "__main__":
    unittest.main()
