#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

class Peripheral:
    def __init__(self, ql):
        self.ql = ql
        self._tag = ''

    def step(self):
        pass

    def read_word(self, offset):
        return b'\x00\x00\x00\x00'

    def write_word(self, offset, value):
        pass

    def read(self, offset, size):
        if size == 4:
            return self.read_word(offset)
        return b'\x00' * size

    def write(self, offset, size, value):
        if size == 4:
            return self.write_word(offset, value)

    @property
    def tag(self):
        return self._tag

    @tag.setter
    def tag(self, value):
        self._tag = value
