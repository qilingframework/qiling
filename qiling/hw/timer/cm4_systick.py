#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
from qiling.arch.arm_const import IRQ
from qiling.hw.peripheral import QlPeripheral
from qiling.hw.const.cm4_systick import SYSTICK_CTRL


class CortexM4SysTick(QlPeripheral):
    class Type(ctypes.Structure):
        _fields_ = [
            ('CTRL' , ctypes.c_uint32),
            ('LOAD' , ctypes.c_int32),
            ('VAL'  , ctypes.c_int32),
            ('CALIB', ctypes.c_uint32),
        ]

    def __init__(self, ql, label):
        super().__init__(ql, label)

        self.systick = self.struct(
            CALIB = 0xC0000000
        )        
        
        # Maybe we will want to customize the timer speed in the future
        self.ratio = 1

    def set_ratio(self, ratio):
        self.ratio = ratio

    def step(self):
        if not self.systick.CTRL & SYSTICK_CTRL.ENABLE:
            return

        if self.systick.VAL <= 0:
            self.systick.VAL = self.systick.LOAD
            self.systick.CTRL |= SYSTICK_CTRL.COUNTFLAG

            if self.systick.CTRL & SYSTICK_CTRL.TICKINT:
                self.ql.hw.nvic.set_pending(IRQ.SYSTICK)
        else:
            self.systick.VAL -= self.ratio

    def read(self, offset: int, size: int) -> int:       
        self.ql.log.debug(f'[{self.label.upper()}] [R] {self.find_field(offset, size):10s}')

        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.systick) + offset, size)

        if offset == self.struct.CTRL.offset:
            self.systick.CTRL &= ~SYSTICK_CTRL.COUNTFLAG        
        return int.from_bytes(buf.raw, byteorder='little')

    def write(self, offset: int, size: int, value: int):
        self.ql.log.debug(f'[{self.label.upper()}] [W] {self.find_field(offset, size):10s} = {hex(value)}')
        
        # ignore the reserved bit
        if offset == self.struct.CTRL.offset:
            value &= SYSTICK_CTRL.MASK
        else:
            value &= 0xffffff # only low-24 bit available

        # restart the timer
        if offset == self.struct.LOAD.offset:            
            self.systick.VAL = value

        data = (value).to_bytes(size, 'little')
        ctypes.memmove(ctypes.addressof(self.systick) + offset, data, size)        
