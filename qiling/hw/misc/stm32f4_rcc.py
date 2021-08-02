#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.hw.peripheral import QlPeripheral


class STM32F4RCC(QlPeripheral):
    def __init__(self, ql, tag):
        super().__init__(ql, tag)
        self.mem = {}

    def read(self, offset, size):
        # print('a')
        ## TODO: Temporary plan, wait for me to implement uart and then change it.
        if offset == 0:
            return 0xffff
        return 0
