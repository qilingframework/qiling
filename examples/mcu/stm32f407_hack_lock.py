#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from multiprocessing import Pool

import sys
sys.path.append("../..")

from qiling.core import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
from qiling.extensions.mcu.stm32f4 import stm32f407


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
                archtype=QL_ARCH.CORTEX_M, ostype=QL_OS.MCU, env=stm32f407, verbose=QL_VERBOSE.DISABLED)

    ql.hw.create('spi2')
    ql.hw.create('gpioe')
    ql.hw.create('gpiof')
    ql.hw.create('usart1')
    ql.hw.create('rcc')

    ql.hw.show_info()

    print('Testing passwd', passwd)

    ql.patch(0x8000238, b'\x00\xBF' * 4)
    ql.patch(0x80031e4, b'\x00\xBF' * 11)
    ql.patch(0x80032f8, b'\x00\xBF' * 13)
    ql.patch(0x80013b8, b'\x00\xBF' * 10)

    ql.hw.usart1.send(passwd.encode() + b'\r')

    ql.hw.systick.set_ratio(100)
    ql.run(count=1000000, end=0x8003225)
    if ql.arch.effective_pc == 0x8003225:
        print('Success, the passwd is', passwd)
    else:
        print('Fail, the passwd is not', passwd)

    del ql


pool = Pool()
for passwd in dicts():
    pool.apply_async(crack, args=(passwd,))

pool.close()
pool.join()
