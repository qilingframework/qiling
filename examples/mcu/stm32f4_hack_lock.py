#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


import sys
sys.path.append("../..")

from qiling.core import Qiling
from qiling.const import QL_VERBOSE
        

ql = Qiling(["../../examples/rootfs/mcu/stm32f407/kjlock.hex"],                    
                    archtype="cortex_m", profile="stm32f407", verbose=QL_VERBOSE.DEFAULT)

ql.hw.show_info()
ql.mem.show_mapinfo()

ql.patch(0x80031e4, b'\x00\xBF' * 11)
ql.patch(0x80032f8, b'\x00\xBF' * 13)
ql.patch(0x80013b8, b'\x00\xBF' * 10)

print('Start')
ql.run(end=0x80031e0|1)
ql.run(count=100, end=0x8003200|1)

# ql.hw.usart1.send(b'618618\r')
ql.hw.usart1.send(b'778899\r')

for _ in range(7):
    ql.run(end=0x8003216|1)
    print('Input:', chr(ql.reg.read('r0')))

ql.run(end=0x8003224|1)
print('Success')
