#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.core import Qiling


class QlPeripheral:
    class Type(ctypes.Structure):
        _fields_ = []
    
    def __init__(self, ql: Qiling, label: str):
        self.ql = ql
        self.label = label
        self.struct = type(self).Type

    def step(self):
        pass

    def read(self, offset: int, size: int) -> int:
        self.ql.log.debug(f'[{self.label.upper()}] [R] {self.find_field(offset, size):10s}')
        return 0

    def write(self, offset: int, size: int, value: int):
        self.ql.log.debug(f'[{self.label.upper()}] [W] {self.find_field(offset, size):10s} = {hex(value)}')        

    def in_field(self, field, offset, size):
        return field.offset <= offset and offset + size <= field.offset + field.size

    def find_field(self, offset, size) -> str:
        for name, _ in self.struct._fields_:
            field = getattr(self.struct, name)
            if (offset, size) == (field.offset, field.size):
                return name
            if self.in_field(field, offset, size):
                return f'{name}[{offset - field.offset}:{offset - field.offset + size}]'

    @property
    def region(self):
        return [(0, ctypes.sizeof(self.struct))]

    @property
    def size(self):
        return sum(rbound-lbound for lbound, rbound in self.region)

    @property
    def base(self):
        return self.ql.hw.region[self.label][0][0]
