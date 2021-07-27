#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import struct
from qiling.dev.peripheral.peripheral import Peripheral

class USART(Peripheral):
    SR = 0x00
    DR = 0x04
    BRR = 0x08
    CR1 = 0x0C
    CR2 = 0x10
    CR3 = 0x14
    GTPR = 0x18

    def __init__(self, ql):
        super().__init__(ql)
        self.mem = { 
            USART.SR: 0xc0, 
            USART.DR: 0x00,
            USART.BRR: 0x00,
            USART.CR1: 0x00,
            USART.CR2: 0x00,
            USART.CR3: 0x00,
            USART.GTPR: 0x00,
        }

    def read_word(self, offset):
        retval = self.mem[offset]
        return struct.pack('<I', retval)

    def write_word(self, offset, value):
        self.mem[offset] = value
        if offset == USART.DR:
            self.ql.log.info('[%s-OUTPUT] %s' % (self.name, repr(chr(value))))

    @property
    def name(self):
        return 'USART'