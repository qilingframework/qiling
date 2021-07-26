#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

class Peripheral:
    def __init__(self, ql):
        self.ql = ql

    def step(self):
        pass

    def readDoubleWord(self, offset):
        return b'\x00\x00\x00\x00'

    def writeDoubleWord(self, offset, value):
        pass

    def read(self, offset, size):
        if size == 4:
            return self.readDoubleWord(offset)
        return b'\x00' * size

    def write(self, offset, size, value):
        if size == 4:
            return self.writeDoubleWord(offset, value)

    @property
    def name(self):
        return 'unknown'