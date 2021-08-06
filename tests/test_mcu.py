#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


import sys, unittest
sys.path.append("..")

from qiling.core import Qiling
from qiling.const import QL_VERBOSE
        

class MCUTest(unittest.TestCase):
    def test_mcu_led_stm32f411(self):
        ql = Qiling(["../examples/rootfs/stm32f411/hex/rand_blink.hex"],                    
                    archtype="cortex_m", profile="stm32f411", verbose=QL_VERBOSE.DISASM)

        # Set verbose=QL_VERBOSE.DEFAULT to find warning
        ql.run(count=1000)

        del ql

    def test_mcu_usart_output_stm32f411(self):
        ql = Qiling(["../examples/rootfs/stm32f411/hex/hello_usart.hex"],                    
                    archtype="cortex_m", profile="stm32f411", verbose=QL_VERBOSE.DEFAULT)
        
        # create/remove
        ql.hw.create('USART', 'usart2', (0x40004400, 0x40004800))
        ql.hw.create('STM32F4RCC', 'rcc', (0x40023800, 0x40023C00))
        
        ql.run(count=2000)
        buf = ql.hw.usart2.recv()
        print('[1] Received from usart: ', buf)
        self.assertEqual(buf, b'Hello USART\n')

        ql.run(count=40000)
        buf = ql.hw.usart2.recv()
        print('[2] Received from usart: ', buf)
        self.assertEqual(buf, b'Hello USART\n')

        del ql

    def test_mcu_usart_input_stm32f411(self):
        ql = Qiling(["../examples/rootfs/stm32f411/hex/md5_server.hex"],                    
            archtype="cortex_m", profile="stm32f411", verbose=QL_VERBOSE.OFF)
        
        ql.hw.create('USART', 'usart2', (0x40004400, 0x40004800))
        ql.hw.create('STM32F4RCC', 'rcc', (0x40023800, 0x40023C00))


        ql.run(count=1000)
        
        ql.hw.usart2.send(b'Hello\n')
        ql.run(count=30000)

        buf = ql.hw.usart2.recv()
        print('[1] Received from usart: ', buf)
        self.assertEqual(buf, b'8b1a9953c4611296a827abf8c47804d7\n')

        ql.hw.usart2.send(b'USART\n')
        ql.run(count=30000)

        buf = ql.hw.usart2.recv()
        print('[2] Received from usart: ', buf)
        self.assertEqual(buf, b'2daeb613094400290a24fe5086c68f06\n')


        ql.hw.usart2.send(b'Input\n')
        ql.run(count=30000)
        
        buf = ql.hw.usart2.recv()
        print('[3] Received from usart: ', buf)
        self.assertEqual(buf, b'324118a6721dd6b8a9b9f4e327df2bf5\n')


if __name__ == "__main__":
    unittest.main()

