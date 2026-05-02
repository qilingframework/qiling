#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral
from qiling.hw.connectivity import QlConnectivityPeripheral
from qiling.hw.const.mk64f12_spi import SR, PUSHR


class MK64F12Spi(QlConnectivityPeripheral):
    class Type(ctypes.Structure):
        """ Serial Peripheral Interface """  
        _fields_ = [
            ("MCR"        , ctypes.c_uint32),     # Module Configuration Register
            ("RESERVED0"  , ctypes.c_uint8 * 4),
            ("TCR"        , ctypes.c_uint32),     # Transfer Count Register
            ("CTAR"       , ctypes.c_uint32 * 2), # Clock and Transfer Attributes Register (In Master Mode)            
            ("RESERVED1"  , ctypes.c_uint8 * 24),
            ("SR"         , ctypes.c_uint32),     # Status Register
            ("RSER"       , ctypes.c_uint32),     # DMA/Interrupt Request Select and Enable Register
            ("PUSHR"      , ctypes.c_uint32),     # PUSH TX FIFO Register In Master Mode            
            ("POPR"       , ctypes.c_uint32),     # POP RX FIFO Register
            ("TXFR"       , ctypes.c_uint32 * 4), # Transmit FIFO Registers
            ("RESERVED2"  , ctypes.c_uint8 * 48),
            ("RXFR"       , ctypes.c_uint32 * 4), # Receive FIFO Registers
        ]

    def __init__(self, ql, label, intn=None):
        super().__init__(ql, label)
        
        self.intn = intn

    @QlPeripheral.monitor()
    def read(self, offset, size):
        if offset == self.struct.POPR.offset:
            if self.has_input():
                self.instance.SR &= ~SR.RFDF
                self.instance.SR &= ~SR.RXCTR
                return self.recv_from_user()

        return self.raw_read(offset, size)
    
    @QlPeripheral.monitor()
    def write(self, offset, size, value):
        if offset == self.struct.PUSHR.offset:
            self.send_to_user(value & PUSHR.TXDATA)
        
        elif offset == self.struct.CTAR.offset:
            self.instance.SR |= SR.TFFF

        self.raw_write(offset, size, value)

    def step(self):
        if self.has_input():
            self.instance.SR |= SR.RFDF
            self.instance.SR |= SR.RXCTR
