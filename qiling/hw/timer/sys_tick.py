#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.hw.peripheral import QlPeripheral


class SysTick(QlPeripheral):
    STK_CTRL  = 0
    STK_LOAD  = 1
    STK_VAL   = 2
    STK_CALIB = 3

    def __init__(self, ql, tag):
        super().__init__(ql, tag)

        self.stk_ctrl  = 0x00000000
        self.stk_load  = 0x00000010
        self.stk_val   = 0x00000000
        self.stk_calib = 0xC0000000

    def step(self):
        if self.stk_val == 0:
            self.ql.hw.nvic.set_pending(-1)
            self.stk_val = self.stk_load
        
        self.stk_val -= 1
