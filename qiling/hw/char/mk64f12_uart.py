#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral
from qiling.hw.connectivity import QlConnectivityPeripheral
from qiling.hw.const.mk64f12_uart import S1, C2, PFIFO


class MK64F12Uart(QlConnectivityPeripheral):
    class Type(ctypes.Structure):
        """ Serial Communication Interface """  
        _fields_ = [
            ("BDH"     , ctypes.c_uint8), # UART Baud Rate Registers: High
            ("BDL"     , ctypes.c_uint8), # UART Baud Rate Registers: Low
            ("C1"      , ctypes.c_uint8), # UART Control Register 1
            ("C2"      , ctypes.c_uint8), # UART Control Register 2
            ("S1"      , ctypes.c_uint8), # UART Status Register 1
            ("S2"      , ctypes.c_uint8), # UART Status Register 2
            ("C3"      , ctypes.c_uint8), # UART Control Register 3
            ("D"       , ctypes.c_uint8), # UART Data Register
            ("MA1"     , ctypes.c_uint8), # UART Match Address Registers 1
            ("MA2"     , ctypes.c_uint8), # UART Match Address Registers 2
            ("C4"      , ctypes.c_uint8), # UART Control Register 4
            ("C5"      , ctypes.c_uint8), # UART Control Register 5
            ("ED"      , ctypes.c_uint8), # UART Extended Data Register
            ("MODEM"   , ctypes.c_uint8), # UART Modem Register
            ("IR"      , ctypes.c_uint8), # UART Infrared Register
            ("RESERVED0", ctypes.c_uint8),
            ("PFIFO"   , ctypes.c_uint8), # UART FIFO Parameters
            ("CFIFO"   , ctypes.c_uint8), # UART FIFO Control Register
            ("SFIFO"   , ctypes.c_uint8), # UART FIFO Status Register
            ("TWFIFO"  , ctypes.c_uint8), # UART FIFO Transmit Watermark
            ("TCFIFO"  , ctypes.c_uint8), # UART FIFO Transmit Count
            ("RWFIFO"  , ctypes.c_uint8), # UART FIFO Receive Watermark
            ("RCFIFO"  , ctypes.c_uint8), # UART FIFO Receive Count
            ("RESERVED1", ctypes.c_uint8),
            ("C7816"   , ctypes.c_uint8), # UART 7816 Control Register
            ("IE7816"  , ctypes.c_uint8), # UART 7816 Interrupt Enable Register
            ("IS7816"  , ctypes.c_uint8), # UART 7816 Interrupt Status Register
            ("WP7816T0", ctypes.c_uint8), # UART 7816 Wait Parameter Register
            ("WN7816"  , ctypes.c_uint8), # UART 7816 Wait N Register
            ("WF7816"  , ctypes.c_uint8), # UART 7816 Wait FD Register
            ("ET7816"  , ctypes.c_uint8), # UART 7816 Error Threshold Register
            ("TL7816"  , ctypes.c_uint8), # UART 7816 Transmit Length Register
        ]

    def __init__(self, ql, label, 
            lon_intn   = None,
            rx_tx_intn = None,
            err_intn   = None
        ):
        super().__init__(ql, label)

        self.lon_intn = lon_intn
        self.rx_tx_intn = rx_tx_intn
        self.err_intn = err_intn

        self.instance = self.struct(
            S1 = S1.TDRE | S1.TC
        )

    @QlPeripheral.monitor()
    def write(self, offset, size, value):
        if offset == self.struct.D.offset:
            self.send_to_user(value)
        else:
            self.raw_write(offset, size, value)

    @QlPeripheral.monitor()
    def read(self, offset, size):
        if offset == self.struct.D.offset:
            if self.instance.PFIFO & PFIFO.RXFE:
                self.instance.RCFIFO = 0
            else:
                self.instance.S1 &= ~S1.RDRF
            return self.recv_from_user()
        
        return self.raw_read(offset, size)

    def step(self):
        if self.has_input():
            if self.instance.PFIFO & PFIFO.RXFE:
                self.instance.RCFIFO = 1
            else:
                self.instance.S1 |= S1.RDRF
            
            if self.instance.C2 & C2.RIE:
                self.ql.hw.nvic.set_pending(self.rx_tx_intn)
