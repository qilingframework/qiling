#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral
from qiling.hw.const.mk64f12_port import PCR, InterruptMode


class MK64F12Port(QlPeripheral):
    class Type(ctypes.Structure):
        """ Pin Control and Interrupts """  
        _fields_ = [
            ("PCR" , ctypes.c_uint32 * 32), # Pin Control Register n
            ("GPCLR", ctypes.c_uint32), # Global Pin Control Low Register
            ("GPCHR", ctypes.c_uint32), # Global Pin Control High Register
            ("RESERVED0", ctypes.c_uint8 * 24),
            ("ISFR" , ctypes.c_uint32), # Interrupt Status Flag Register
            ("RESERVED1", ctypes.c_uint8 * 28),
            ("DFER" , ctypes.c_uint32), # Digital Filter Enable Register
            ("DFCR" , ctypes.c_uint32), # Digital Filter Clock Register
            ("DFWR" , ctypes.c_uint32), # Digital Filter Width Register
        ]

    def __init__(self, ql, label, intn=None):
        super().__init__(ql, label)

        self.intn = intn

    def pin_interrupt_config(self, index):
        return (self.instance.PCR[index] & PCR.IRQC) >> 16

    def send_interrupt(self, index, prev, curr): 
        config = self.pin_interrupt_config(index)       
        if (
            (config == InterruptMode.InterruptLogicZero   and curr == 0) or
            (config == InterruptMode.InterruptLogicOne    and curr == 1) or
            (config == InterruptMode.InterruptRisingEdge  and curr == 1 and prev == 0) or
            (config == InterruptMode.InterruptFallingEdge and curr == 0 and prev == 1) or
            (config == InterruptMode.InterruptEitherEdge  and curr != prev)
        ):
            self.ql.hw.nvic.set_pending(self.intn)
