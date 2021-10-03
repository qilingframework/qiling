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
        ql = Qiling(["../examples/rootfs/mcu/stm32f411/rand_blink.hex"],                    
                    archtype="cortex_m", profile="stm32f411", verbose=QL_VERBOSE.DISASM)

        # Set verbose=QL_VERBOSE.DEFAULT to find warning
        ql.run(count=1000)

        del ql

    def test_mcu_usart_output_stm32f411(self):
        ql = Qiling(["../examples/rootfs/mcu/stm32f411/hello_usart.hex"],                    
                    archtype="cortex_m", profile="stm32f411", verbose=QL_VERBOSE.DEFAULT)        
        
        ql.hw.create('usart2')
        ql.hw.create('rcc')

        ql.run(count=2000)
        buf = ql.hw.usart2.recv()
        print('[1] Received from usart: ', buf)
        self.assertEqual(buf, b'Hello USART\n')

        del ql

    def test_mcu_usart_input_stm32f411(self):
        ql = Qiling(["../examples/rootfs/mcu/stm32f411/md5_server.hex"],                    
            archtype="cortex_m", profile="stm32f411", verbose=QL_VERBOSE.OFF)

        ql.hw.create('usart2')
        ql.hw.create('rcc')
        
        ql.run(count=1000)
        
        ql.hw.usart2.send(b'Hello\n')
        ql.run(count=30000)
        ql.hw.usart2.send(b'USART\n')
        ql.run(count=30000)
        ql.hw.usart2.send(b'Input\n')
        ql.run(count=30000)
        
        buf = ql.hw.usart2.recv()
        self.assertEqual(buf, b'8b1a9953c4611296a827abf8c47804d7\n2daeb613094400290a24fe5086c68f06\n324118a6721dd6b8a9b9f4e327df2bf5\n')

        del ql

    def test_mcu_patch_stm32f411(self):
        ql = Qiling(["../examples/rootfs/mcu/stm32f411/patch_test.hex"],                    
                    archtype="cortex_m", profile="stm32f411", verbose=QL_VERBOSE.DEFAULT)

        ql.hw.create('usart2')
        ql.hw.create('rcc')
        ql.hw.create('gpioa')

        ql.patch(0x80005CA, b'\x00\xBF')
        ql.run(count=4000)

        del ql

    def test_mcu_freertos_stm32f411(self):
        ql = Qiling(["../examples/rootfs/mcu/stm32f411/os-demo.bin", 0x8000000],                    
            archtype="cortex_m", profile="stm32f411", verbose=QL_VERBOSE.DEBUG)

        ql.hw.create('usart2')
        ql.hw.create('rcc')
        ql.hw.create('gpioa')

        count = 0
        def counter():
            nonlocal count
            count += 1

        ql.hw.gpioa.hook_set(5, counter)

        ql.run(count=200000)

        self.assertTrue(count >= 5)
        self.assertTrue(ql.hw.usart2.recv().startswith(b'Free RTOS\n' * 5))

        del ql

    def test_mcu_dma_stm32f411(self):
        ql = Qiling(["../examples/rootfs/mcu/stm32f411/dma-clock.hex"],                    
            archtype="cortex_m", profile="stm32f411", verbose=QL_VERBOSE.DEBUG)

        ql.hw.create('usart2')
        ql.hw.create('dma1')
        ql.hw.create('rcc')

        ql.run(count=200000)
        buf = ql.hw.usart2.recv()

        ## check timestamp
        tick = [int(x) for x in buf.split()]
        for i in range(1, len(tick)):
            assert(4 <= tick[i] - tick[i - 1] <= 6)

        del ql

    def test_mcu_i2c_stm32f411(self):
        ql = Qiling(["../examples/rootfs/mcu/stm32f411/i2c-lcd.bin", 0x8000000],
            archtype="cortex_m", profile="stm32f411", verbose=QL_VERBOSE.DEBUG)

        ql.hw.create('i2c1')
        ql.hw.create('rcc')
        ql.hw.create('gpioa')
        ql.hw.create('gpiob')

        flag = False
        def indicator():
            nonlocal flag
            flag = True

        ql.hw.gpioa.hook_set(5, indicator)

        class LCD:
            address = 0x3f << 1

        ql.hw.i2c1.connect(LCD())
        ql.run(count=550000)

        self.assertTrue(flag)

        del ql

    def test_mcu_spi_stm32f411(self):
        ql = Qiling(["../examples/rootfs/mcu/stm32f411/spi-test.hex"],
            archtype="cortex_m", profile="stm32f411", verbose=QL_VERBOSE.DEBUG)

        ql.hw.create('spi1')
        ql.hw.create('rcc')
        ql.hw.create('usart2')
        ql.hw.create('gpioa')

        ql.run(count=30000)
        self.assertTrue(ql.hw.usart2.recv() == b'----------------SPI TEST----------------\najcmfoiblenhakdmgpjclfoibkengajd\nmfpicleohbkdngajcmfoiblenhakdmgp\njclfoibkengajdmfpicleohbkdngajcm\nfoiblenhakdmgpjclfoibkengajdmfpi\ncleohbkdngajcmfoiblenhakdmgpjclf\noibkenhajdmfpicleohbkdngajcmfpib\nlenhakdmgpjclfoibkenhajdmfpicleo\nhbkdngajcmfpiblenhakdmgpjclfoibk\n----------------TEST END----------------\n')

        del ql

if __name__ == "__main__":
    unittest.main()

