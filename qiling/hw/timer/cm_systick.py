#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
from qiling.arch.cortex_m_const import IRQ
from qiling.hw.peripheral import QlPeripheral
from qiling.hw.timer.timer import QlTimerPeripheral
from qiling.hw.const.cm4_systick import SYSTICK_CTRL


class CortexMSysTick(QlTimerPeripheral):
    class Type(ctypes.Structure):
        _fields_ = [
            ('CTRL' , ctypes.c_uint32),
            ('LOAD' , ctypes.c_int32),
            ('VAL'  , ctypes.c_int32),
            ('CALIB', ctypes.c_uint32),
        ]

    def __init__(self, ql, label):
        super().__init__(ql, label)

        self.instance = self.struct(
            CALIB = 0xC0000000
        )

    def step(self):
        if not self.instance.CTRL & SYSTICK_CTRL.ENABLE:
            return

        if self.instance.VAL <= 0:
            self.instance.CTRL |= SYSTICK_CTRL.COUNTFLAG
            self.instance.VAL = self.instance.LOAD
            
        else:
            self.instance.VAL -= self.ratio

            if self.instance.VAL <= 0:                
                if self.instance.CTRL & SYSTICK_CTRL.TICKINT:
                    self.ql.hw.nvic.set_pending(IRQ.SYSTICK)

    @QlPeripheral.monitor()
    def read(self, offset: int, size: int) -> int:
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.instance) + offset, size)

        if offset == self.struct.CTRL.offset:
            self.instance.CTRL &= ~SYSTICK_CTRL.COUNTFLAG        
        return int.from_bytes(buf.raw, byteorder='little')

    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):
        # ignore the reserved bit
        if offset == self.struct.CTRL.offset:
            value &= SYSTICK_CTRL.MASK
        else:
            value &= 0xffffff # only low-24 bit available

        # restart the timer
        if offset == self.struct.LOAD.offset:            
            self.instance.VAL = value

        data = (value).to_bytes(size, 'little')
        ctypes.memmove(ctypes.addressof(self.instance) + offset, data, size)        
