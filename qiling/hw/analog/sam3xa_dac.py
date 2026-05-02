#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral
from qiling.hw.const.sam3xa_dac import ISR


class SAM3xaDac(QlPeripheral):
    class Type(ctypes.Structure):
        """ Digital-to-Analog Converter Controller """  
        _fields_ = [
            ("CR"  , ctypes.c_uint32), # Control Register
            ("MR"  , ctypes.c_uint32), # Mode Register
            ("Reserved1", ctypes.c_uint32 * 2),
            ("CHER", ctypes.c_uint32), # Channel Enable Register
            ("CHDR", ctypes.c_uint32), # Channel Disable Register
            ("CHSR", ctypes.c_uint32), # Channel Status Register
            ("Reserved2", ctypes.c_uint32),
            ("CDR" , ctypes.c_uint32), # Conversion Data Register
            ("IER" , ctypes.c_uint32), # Interrupt Enable Register
            ("IDR" , ctypes.c_uint32), # Interrupt Disable Register
            ("IMR" , ctypes.c_uint32), # Interrupt Mask Register
            ("ISR" , ctypes.c_uint32), # Interrupt Status Register
            ("Reserved3", ctypes.c_uint32 * 24),
            ("ACR" , ctypes.c_uint32), # Analog Current Register
            ("Reserved4", ctypes.c_uint32 * 19),
            ("WPMR", ctypes.c_uint32), # Write Protect Mode register
            ("WPSR", ctypes.c_uint32), # Write Protect Status register
            ("Reserved5", ctypes.c_uint32 * 7),
            ("TPR" , ctypes.c_uint32), # Transmit Pointer Register
            ("TCR" , ctypes.c_uint32), # Transmit Counter Register
            ("Reserved6", ctypes.c_uint32 * 2),
            ("TNPR", ctypes.c_uint32), # Transmit Next Pointer Register
            ("TNCR", ctypes.c_uint32), # Transmit Next Counter Register
            ("PTCR", ctypes.c_uint32), # Transfer Control Register
            ("PTSR", ctypes.c_uint32), # Transfer Status Register
        ]

    def __init__(self, ql, label, intn=None):
        super().__init__(ql, label)

        self.intn = intn

    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):
        if offset == self.struct.CDR.offset:
            self.instance.ISR |= ISR.EOC

        data = (value).to_bytes(size, 'little')
        ctypes.memmove(ctypes.addressof(self.instance) + offset, data, size)
