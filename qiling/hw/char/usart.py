#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import struct
from qiling.hw.peripheral import QlPeripheral
from qiling.hw.core.register import PeripheralRegisterGroup

class Usart(QlPeripheral, PeripheralRegisterGroup):
    SR = 0x00
    DR = 0x04
    BRR = 0x08
    CR1 = 0x0C
    CR2 = 0x10
    CR3 = 0x14
    GTPR = 0x18

    def __init__(self, ql, base_addr):
        super().__init__(ql, base_addr)
        self.mem = { 
            Usart.SR: 0xc0, 
            Usart.DR: 0x00,
            Usart.BRR: 0x00,
            Usart.CR1: 0x00,
            Usart.CR2: 0x00,
            Usart.CR3: 0x00,
            Usart.GTPR: 0x00,
        }

    def read_double_word(self, offset):
        retval = self.mem[offset]
        return struct.pack('<I', retval)

    def write_double_word(self, offset, value):
        self.mem[offset] = value
        if offset == Usart.DR:
            self.ql.log.info('[%s] %s' % (self.tag, repr(chr(value))))
