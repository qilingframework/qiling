#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from .peripheral import Peripheral

class SysTickTimer(Peripheral):
    STK_CTRL  = 0
    STK_LOAD  = 1
    STK_VAL   = 2
    STK_CALIB = 3

    def __init__(self, ql):
        super().__init__(ql)

        self.stk_ctrl  = 0x00000000
        self.stk_load  = 0x00000010
        self.stk_val   = 0x00000000
        self.stk_calib = 0xC0000000

    def step(self):
        if self.stk_val == 0:
            self.ql.arch.nvic.send_interrupt(15)
            self.stk_val = self.stk_load
        
        self.stk_val -= 1
