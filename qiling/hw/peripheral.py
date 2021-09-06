#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes


class QlPeripheral:
    class Type(ctypes.Structure):
        _fields_ = []
    
    def __init__(self, ql, label, **kwargs):
        self.ql = ql
        self.label = label
        self.struct = type(self).Type

    def step(self):
        pass

    def read(self, offset, size) -> int:
        self.ql.log.debug('[%s] Read [0x%08x:%d]' % (self.label, offset, size))
        return 0

    def write(self, offset, size, value):
        self.ql.log.debug('[%s] Write [0x%08x:%d] = %08x' % (self.label, offset, size, value))

    @property
    def region(self):
        return [(0, ctypes.sizeof(self.struct))]

    @property
    def size(self):
        return sum(rbound-lbound for lbound, rbound in self.region)

    @property
    def base(self):
        return self.ql.hw.region[self.label][0][0]
