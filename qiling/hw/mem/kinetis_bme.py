#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.hw.peripheral import QlPeripheral
from qiling.exception import QlErrorNotImplemented

class KinetisBME(QlPeripheral):

    def __init__(self, ql, label, base, size):
        super().__init__(ql, label)

        self.bme_base = base
        self.bme_size = size

    @property
    def region(self):
        return [(0, 0x10000000)]

    def operand_size_from_alignment(self, addr):
        if addr & 1:
            return 1
        elif addr & 2:
            return 2
        else:
            return 4

    def read(self, offset, size):
        raise QlErrorNotImplemented("KinetisBME.read has not been implemented")

    def write(self, offset, size, value):
        decorated_addr = offset + self.base
        read_size = self.operand_size_from_alignment(decorated_addr)

        op_type = (decorated_addr & 0x1c000000) >> 26
        address = decorated_addr & 0x6007ffff

        raw = self.ql.read(address, read_size)

        if   op_type == 0x1:
            raw &= value
        elif op_type == 0x2:
            raw |= value
        else:
            ## TODO: other operands
            raise QlErrorNotImplemented(f"operand ({hex(op_type)}) has not been implemented")
        
        self.ql.write(address, read_size, raw)
        