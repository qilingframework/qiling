#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.hw.peripheral import QlPeripheral


class MemoryRemap(QlPeripheral):
    def __init__(self, ql, label, base, size):
        super().__init__(ql, label)

        self.remap_base = base
        self.remap_size = size

    @property
    def region(self):
        return [(0, self.remap_size)]

    def read(self, offset, size):
        return int.from_bytes(self.ql.mem.read(self.remap_base + offset, size), 'little')

    def write(self, offset, size, value):
        return self.ql.mem.write(self.remap_base + offset, (value).to_bytes(size, 'little'))
