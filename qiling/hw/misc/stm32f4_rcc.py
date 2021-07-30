#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.hw.peripheral import QlPeripheral


class Stm32f4Rcc(QlPeripheral):
    def __init__(self, ql):
        super().__init__(ql)
        self.mem = {}

    def read_double_word(self, offset):
        ## TODO: Temporary plan, wait for me to implement uart and then change it.
        if offset == 0:
            return b'\xff\xff\x00\x00'
        return b'\x00\x00\x00\x00'
