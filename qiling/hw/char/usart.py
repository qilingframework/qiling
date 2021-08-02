#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import struct
from qiling.hw.peripheral import QlPeripheral

class USART(QlPeripheral):
    SR = 0x00
    DR = 0x04
    BRR = 0x08
    CR1 = 0x0C
    CR2 = 0x10
    CR3 = 0x14
    GTPR = 0x18

    def __init__(self, ql, tag):
        super().__init__(ql, tag)
        self.mem = { 
            USART.SR: 0xc0, 
            USART.DR: 0x00,
            USART.BRR: 0x00,
            USART.CR1: 0x00,
            USART.CR2: 0x00,
            USART.CR3: 0x00,
            USART.GTPR: 0x00,
        }

    def read(self, offset, size):
        retval = self.mem[offset]
        return retval

    def write(self, offset, size, value):
        self.mem[offset] = value
        if offset == USART.DR:
            self.ql.log.info('[usart] %s' % (repr(chr(value))))
