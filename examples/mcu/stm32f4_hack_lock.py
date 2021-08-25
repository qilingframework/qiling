#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


import sys
from multiprocessing import Pool
from multiprocessing import Process

sys.path.append("../..")

from qiling.core import Qiling
from qiling.const import QL_VERBOSE

def dicts():
    a = 0x79df7
    b = 0x75ee0
    c = 0xcc5ee
    M = 0xf4247

    for x in range(1, 20):
        yield str((a*x*x + b*x + c) % M)

# Cracking the passwd of lock
def crack(passwd):
    ql = Qiling(["../../examples/rootfs/mcu/stm32f407/backdoorlock.hex"],                    
                        archtype="cortex_m", profile="stm32f407", verbose=QL_VERBOSE.OFF)

    ql.hw.remove('usart2')
    ql.hw.remove('usart3')
    ql.hw.remove('uart4')
    ql.hw.remove('uart5')
    ql.hw.remove('usart6')
    ql.hw.remove('pwr')
    ql.hw.remove('spi1')
    ql.hw.remove('spi2')
    ql.hw.remove('spi3')
    ql.hw.remove('dma1')
    ql.hw.remove('dma2')
    ql.hw.remove('crc')
    ql.hw.remove('rcc')
    ql.hw.remove('gpioa')
    ql.hw.remove('gpiob')
    ql.hw.remove('gpioc')
    ql.hw.remove('gpiod')
    ql.hw.remove('gpioe')
    ql.hw.remove('gpiof')
    ql.hw.remove('gpiog')
    ql.hw.remove('gpioh')
    ql.hw.remove('gpioi')
    ql.hw.remove('i2s2ext')
    ql.hw.remove('i2s3ext')
    ql.hw.remove('exti')
    ql.hw.remove('syscfg')

    ql.hw.show_info()

    print('Testing passwd', passwd)

    ql.patch(0x8000238, b'\x00\xBF' * 4)
    ql.patch(0x80031e4, b'\x00\xBF' * 11)
    ql.patch(0x80032f8, b'\x00\xBF' * 13)
    ql.patch(0x80013b8, b'\x00\xBF' * 10)

    ql.hw.usart1.send(passwd.encode() + b'\r')

    ql.run(count=300000, end=0x8003225)
    if ql.arch.get_pc() == 0x8003225:
        print('Success, the passwd is', passwd)
    else:
        print('Fail, the passwd is not', passwd)

    del ql
    
pool = Pool()
for passwd in dicts():
    pool.apply_async(crack, args=(passwd,))

pool.close()
pool.join()
