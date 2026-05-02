#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral
from qiling.hw.connectivity import QlConnectivityPeripheral
from qiling.hw.const.sam3xa_spi import SR, TDR


class SAM3xaSpi(QlConnectivityPeripheral):
    class Type(ctypes.Structure):
        """ Serial Peripheral Interface (SPI) """  
        _fields_ = [
            ("CR"  , ctypes.c_uint32), # Control Register
            ("MR"  , ctypes.c_uint32), # Mode Register
            ("RDR" , ctypes.c_uint32), # Receive Data Register
            ("TDR" , ctypes.c_uint32), # Transmit Data Register
            ("SR"  , ctypes.c_uint32), # Status Register
            ("IER" , ctypes.c_uint32), # Interrupt Enable Register
            ("IDR" , ctypes.c_uint32), # Interrupt Disable Register
            ("IMR" , ctypes.c_uint32), # Interrupt Mask Register
            ("Reserved1", ctypes.c_uint32 * 4),
            ("CSR" , ctypes.c_uint32 * 4), # Chip Select Register
            ("Reserved2", ctypes.c_uint32 * 41),
            ("WPMR", ctypes.c_uint32), # Write Protection Control Register
            ("WPSR", ctypes.c_uint32), # Write Protection Status Register
        ]

    def __init__(self, ql, label, intn=None):
        super().__init__(ql, label)

        self.intn = intn
        self.instance = self.struct(
            SR = SR.TDRE | SR.RDRF,
            RDR = 0xff,
        )

    @QlPeripheral.monitor()
    def read(self, offset, size):
        if offset == self.struct.RDR.offset:
            if self.has_input():
                return self.recv_from_user()
        
        return self.raw_read(offset, size)

    @QlPeripheral.monitor()
    def write(self, offset, size, value):
        if offset == self.struct.TDR.offset:
            self.send_to_user(value & TDR.TD)

        self.raw_write(offset, size, value)