#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes


class QlPeripheral:
    class Type(ctypes.Structure):
        _fields_ = []
    
    def __init__(self, ql, tag, **kwargs):
        self.ql = ql
        self.tag = tag
        self.struct = type(self).Type

    def step(self):
        pass

    def read(self, offset, size) -> int:
        self.ql.log.warning('[%s] Read [0x%08x:%d]' % (self.tag, offset, size))
        return 0

    def write(self, offset, size, value):
        self.ql.log.warning('[%s] Write [0x%08x:%d] = %08x' % (self.tag, offset, size, value))
