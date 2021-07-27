#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.hw.peripheral import Peripheral

class SystemControlBlock(Peripheral):
    def __init__(self, ql):
        super().__init__(ql)

    ## TODO: Implement specific details

    @property
    def name(self):
        return 'SCB'
