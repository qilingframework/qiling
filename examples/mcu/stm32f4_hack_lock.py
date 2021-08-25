#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


import sys
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
for passwd in dicts():
    ql = Qiling(["../../examples/rootfs/mcu/stm32f407/backdoorlock.hex"],                    
                        archtype="cortex_m", profile="stm32f407", verbose=QL_VERBOSE.OFF)

    print('Try to use', passwd)

    ql.patch(0x80031e4, b'\x00\xBF' * 11)
    ql.patch(0x80032f8, b'\x00\xBF' * 13)
    ql.patch(0x80013b8, b'\x00\xBF' * 10)

    ql.hw.usart1.send(passwd.encode() + b'\r')

    ql.run(count=500000, end=0x8003225)
    if ql.arch.get_pc() == 0x8003225:
        print('Success, the passwd is', passwd)

    del ql
 