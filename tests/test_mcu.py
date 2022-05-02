#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


import sys, unittest
sys.path.append("..")

from qiling.core import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions.mcu.stm32f4 import stm32f407, stm32f411
from qiling.extensions.mcu.stm32f1 import stm32f103
from qiling.extensions.mcu.atmel   import sam3x8e
from qiling.extensions.mcu.gd32vf1 import gd32vf103

class MCUTest(unittest.TestCase):
    def test_mcu_led_stm32f411(self):
        ql = Qiling(["../examples/rootfs/mcu/stm32f411/rand_blink.hex"],                    
                    archtype="cortex_m", env=stm32f411, verbose=QL_VERBOSE.DISASM)

        # Set verbose=QL_VERBOSE.DEFAULT to find warning
        ql.run(count=1000)

        del ql

    def test_mcu_usart_output_stm32f411(self):
        ql = Qiling(["../examples/rootfs/mcu/stm32f411/hello_usart.hex"],                    
                    archtype="cortex_m", env=stm32f411, verbose=QL_VERBOSE.DEFAULT)        
        
        ql.hw.create('usart2')
        ql.hw.create('rcc')

        ql.run(count=2000)
        buf = ql.hw.usart2.recv()
        print('[1] Received from usart: ', buf)
        self.assertEqual(buf, b'Hello USART\n')

        del ql

    def test_mcu_usart_input_stm32f411(self):
        ql = Qiling(["../examples/rootfs/mcu/stm32f411/md5_server.hex"],                    
            archtype="cortex_m", env=stm32f411, verbose=QL_VERBOSE.OFF)

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
                    archtype="cortex_m", env=stm32f411, verbose=QL_VERBOSE.DEFAULT)

        ql.hw.create('usart2')
        ql.hw.create('rcc')
        ql.hw.create('gpioa')

        ql.patch(0x80005CA, b'\x00\xBF')
        ql.run(count=4000)

        del ql

    def test_mcu_freertos_stm32f411(self):
        ql = Qiling(["../examples/rootfs/mcu/stm32f411/os-demo.elf"],
            archtype="cortex_m", env=stm32f411, verbose=QL_VERBOSE.DEBUG)

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
        ql = Qiling(["../examples/rootfs/mcu/stm32f411/dma-clock.elf"],                    
            archtype="cortex_m", env=stm32f411, verbose=QL_VERBOSE.DEFAULT)

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
            archtype="cortex_m", env=stm32f411, verbose=QL_VERBOSE.DEFAULT)

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

            def send(self, data):
                pass

            def step(self):
                pass

        ql.hw.i2c1.connect(LCD())
        ql.run(count=550000)

        self.assertTrue(flag)

        del ql

    def test_mcu_spi_stm32f411(self):
        ql = Qiling(["../examples/rootfs/mcu/stm32f411/spi-test.bin", 0x8000000],
            archtype="cortex_m", env=stm32f411, verbose=QL_VERBOSE.DEFAULT)

        ql.hw.create('spi1')
        ql.hw.create('rcc')
        ql.hw.create('usart2')
        ql.hw.create('gpioa')

        ql.run(count=30000)
        self.assertTrue(ql.hw.usart2.recv() == b'----------------SPI TEST----------------\najcmfoiblenhakdmgpjclfoibkengajd\nmfpicleohbkdngajcmfoiblenhakdmgp\njclfoibkengajdmfpicleohbkdngajcm\nfoiblenhakdmgpjclfoibkengajdmfpi\ncleohbkdngajcmfoiblenhakdmgpjclf\noibkenhajdmfpicleohbkdngajcmfpib\nlenhakdmgpjclfoibkenhajdmfpicleo\nhbkdngajcmfpiblenhakdmgpjclfoibk\n----------------TEST END----------------\n')

        del ql

    def test_mcu_led_rust_stm32f411(self):
        ql = Qiling(["../examples/rootfs/mcu/stm32f411/led-rust.hex"],
                    archtype="cortex_m", env=gd32vf103, profile="profiles/stm32f411.yml", verbose=QL_VERBOSE.DEFAULT)

        count = 0
        def counter():
            nonlocal count
            count += 1            

        ql.hw.create('gpioa').hook_set(5, counter)
        ql.hw.create('rcc')        

        ql.run(count=1000)
        self.assertTrue(count >= 5)

        del ql

    def test_mcu_uart_rust_stm32f411(self): 
        ql = Qiling(["../examples/rootfs/mcu/stm32f411/uart-rust.hex"],
                    archtype="cortex_m", env=stm32f411, verbose=QL_VERBOSE.DEFAULT)

        ## cover env by profiles

        ql.hw.create('rcc')
        ql.hw.create('gpioa')
        ql.hw.create('usart2')

        ql.hw.usart2.send(b'123')
        ql.run(count=10000)
        self.assertTrue(ql.hw.usart2.recv() == b'1')

        del ql

    def test_mcu_hacklock_stm32f407(self):
        def crack(passwd):
            ql = Qiling(["../examples/rootfs/mcu/stm32f407/backdoorlock.hex"],                    
                                archtype="cortex_m", env=stm32f407, verbose=QL_VERBOSE.OFF)
            
            ql.hw.create('spi2')
            ql.hw.create('gpioe')
            ql.hw.create('gpiof')
            ql.hw.create('usart1')
            ql.hw.create('rcc')

            print('Testing passwd', passwd)

            ql.patch(0x8000238, b'\x00\xBF' * 4)
            ql.patch(0x80031e4, b'\x00\xBF' * 11)
            ql.patch(0x80032f8, b'\x00\xBF' * 13)
            ql.patch(0x80013b8, b'\x00\xBF' * 10)

            ql.hw.usart1.send(passwd.encode() + b'\r')

            ql.hw.systick.set_ratio(400)
            
            ql.run(count=400000, end=0x8003225)
            
            return ql.arch.effective_pc == 0x8003225

        self.assertTrue(crack('618618'))
        self.assertTrue(crack('778899'))
        self.assertFalse(crack('123456'))

    def test_mcu_tim_speed_stm32f411(self):
        ql = Qiling(['../examples/rootfs/mcu/stm32f411/basic-timer.elf'], 
                archtype="cortex_m", env=stm32f411, verbose=QL_VERBOSE.DEFAULT)

        ql.hw.create('rcc')
        ql.hw.create('flash interface')
        ql.hw.create('pwr')
        ql.hw.create('gpioa')
        ql.hw.create('usart2')
        ql.hw.create('tim1')


        ql.hw.tim1.set_ratio(1500)
        ql.run(count=2500)

        count = 0
        def counter():
            nonlocal count
            count += 1

        ql.hw.gpioa.hook_set(5, counter)
        ql.run(count=10000)
        count1 = count
        count = 0

        ql.hw.tim1.set_ratio(1400 * 2)
        ql.run(count=10000)
        count2 = count
        count = 0

        ql.hw.tim1.set_ratio(1600 // 2)
        ql.run(count=10000)
        count3 = count
        count = 0

        self.assertTrue(round(count2 / count1) == 2)
        self.assertTrue(round(count1 / count3) == 2)
        self.assertTrue(ql.hw.usart2.recv().startswith(b'hello\n'))

    def test_mcu_i2c_interrupt_stm32f411(self):
        ql = Qiling(['../examples/rootfs/mcu/stm32f411/i2cit-lcd.elf'], 
                archtype="cortex_m", env=stm32f411, verbose=QL_VERBOSE.DEFAULT)

        ql.hw.create('i2c1')
        ql.hw.create('rcc').watch()
        ql.hw.create('gpioa')
        ql.hw.create('gpiob') 

        class LCD:
            address = 0x3f << 1

            def send(self, data):
                pass

            def step(self):
                pass

        lcd = LCD()
        ql.hw.i2c1.connect(lcd)

        ql.hw.systick.set_ratio(100)

        delay_start = 0x8002936
        delay_end = 0x8002955
        def skip_delay(ql):
            ql.arch.regs.pc = delay_end

        ql.hook_address(skip_delay, delay_start)

        ql.run(count=100000)

        del ql


    def test_mcu_blink_gd32vf103(self):
        ql = Qiling(['../examples/rootfs/mcu/gd32vf103/blink.hex'],
            ostype="mcu", archtype="riscv64", env=gd32vf103, verbose=QL_VERBOSE.DEFAULT)

        ql.hw.create('rcu')
        ql.hw.create('gpioa')
        ql.hw.create('gpioc').watch()

        delay_cycles_begin = 0x800015c
        delay_cycles_end = 0x800018c

        def skip_delay(ql):
            ql.arch.regs.pc = delay_cycles_end

        count = 0
        def counter():
            nonlocal count
            count += 1

        ql.hook_address(skip_delay, delay_cycles_begin)
        ql.hw.gpioc.hook_set(13, counter)
        ql.run(count=20000)
        self.assertTrue(count > 350)
        
        del ql

    def test_mcu_crc_stm32f407(self):
        ql = Qiling(["../examples/rootfs/mcu/stm32f407/ai-sine-test.elf"],
            archtype="cortex_m", env=stm32f407, verbose=QL_VERBOSE.DEFAULT)

        ql.hw.create('rcc')
        ql.hw.create('pwr')
        ql.hw.create('flash interface')
        ql.hw.create('gpioa')
        ql.hw.create('gpiob')
        ql.hw.create('gpiod')
        ql.hw.create('spi1')
        ql.hw.create('crc')
        ql.hw.create('dbgmcu')

        flag = False
        def indicator(ql):
            nonlocal flag
            ql.log.info('PA7 set')
            flag = True

        ql.hw.gpioa.hook_set(7, indicator, ql)
        ql.hw.systick.ratio = 1000

        ql.run(count=600000)
        self.assertTrue(flag)

        del ql

    def test_mcu_usart_stm32f103(self):
        ql = Qiling(["../examples/rootfs/mcu/stm32f103/sctf2020-password-lock-plus.hex"],
            archtype="cortex_m", env=stm32f103, verbose=QL_VERBOSE.DEFAULT)

        ql.hw.create('rcc')
        ql.hw.create('flash interface')
        ql.hw.create('exti')
        ql.hw.create('usart1')
        ql.hw.create('gpioa')
        ql.hw.create('afio')
        ql.hw.create('dma1').watch()

        data = []
        def gpio_set_cb(pin):
            data.append(pin)

        ql.hw.gpioa.hook_set(1, gpio_set_cb, '1')
        ql.hw.gpioa.hook_set(2, gpio_set_cb, '2')
        ql.hw.gpioa.hook_set(3, gpio_set_cb, '3')
        ql.hw.gpioa.hook_set(4, gpio_set_cb, '4')

        ql.run(count=400000)
        
        self.assertTrue((''.join(data)).find('1442413') != -1)
        self.assertTrue(ql.hw.usart1.recv()[:23] == b'SCTF{that1s___r1ghtflag')
        
        del ql

    def test_mcu_serial_sam3x8e(self):
        ql = Qiling(["../examples/rootfs/mcu/sam3x8e/serial.ino.hex"],
            archtype="cortex_m", env=sam3x8e, verbose=QL_VERBOSE.DEFAULT)

        ql.hw.create('wdt')
        ql.hw.create('efc0')
        ql.hw.create('efc1')
        ql.hw.create('pmc')
        ql.hw.create('uotghs')
        ql.hw.create('pioa')
        ql.hw.create('piob')
        ql.hw.create('pioc')
        ql.hw.create('piod')
        ql.hw.create('adc')
        ql.hw.create('uart')
        ql.hw.create('pdc_uart')

        ql.hw.systick.ratio = 1000
        ql.run(count=100000)
        self.assertTrue(ql.hw.uart.recv().startswith(b'hello world\nhello world\n'))

        del ql


if __name__ == "__main__":
    unittest.main()

