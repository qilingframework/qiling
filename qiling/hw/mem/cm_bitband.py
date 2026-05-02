#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.hw.peripheral import QlPeripheral


class CortexMBitband(QlPeripheral):
    def __init__(self, ql, label, base, size):
        super().__init__(ql, label)

        self.bitband_base = base
        self.bitband_size = size * 32

    def _bitband_addr(self, offset):
        return self.bitband_base | (offset & 0x1ffffff) >> 5

    @property
    def region(self):
        return [(0, self.bitband_size)]

    def read(self, offset, size):
        addr = self._bitband_addr(offset) & (-size)
        buf = self.ql.mem.read(addr, size)
                    
        bitpos = (offset >> 2) & ((size * 8) - 1)            
        bit = (buf[bitpos >> 3] >> (bitpos & 7)) & 1

        return bit
    
    def write(self, offset, size, value):
        addr = self._bitband_addr(offset) & (-size)            
        buf = self.ql.mem.read(addr, size)
        
        bitpos = (offset >> 2) & ((size * 8) - 1)
        bit = 1 << (bitpos & 7)
        if value & 1:
            buf[bitpos >> 3] |= bit
        else:
            buf[bitpos >> 3] &= ~bit

        self.ql.mem.write(addr, bytes(buf))
