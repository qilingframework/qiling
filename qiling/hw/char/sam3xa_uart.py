#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral
from qiling.hw.connectivity import QlConnectivityPeripheral
from qiling.hw.const.sam3xa_uart import SR


class SAM3xaUart(QlConnectivityPeripheral):
    class Type(ctypes.Structure):
        _fields_ = [
            ("CR"       , ctypes.c_uint32),      # (Uart Offset: 0x0000) Control Register
            ("MR"       , ctypes.c_uint32),      # (Uart Offset: 0x0004) Mode Register
            ("IER"      , ctypes.c_uint32),      # (Uart Offset: 0x0008) Interrupt Enable Register
            ("IDR"      , ctypes.c_uint32),      # (Uart Offset: 0x000C) Interrupt Disable Register
            ("IMR"      , ctypes.c_uint32),      # (Uart Offset: 0x0010) Interrupt Mask Register
            ("SR"       , ctypes.c_uint32),      # (Uart Offset: 0x0014) Status Register
            ("RHR"      , ctypes.c_uint32),      # (Uart Offset: 0x0018) Receive Holding Register
            ("THR"      , ctypes.c_uint32),      # (Uart Offset: 0x001C) Transmit Holding Register
            ("BRGR"     , ctypes.c_uint32),      # (Uart Offset: 0x0020) Baud Rate Generator Register
            ("Reserved1", ctypes.c_uint32 * 55), # 
            ("RPR"      , ctypes.c_uint32),      # (Uart Offset: 0x100) Receive Pointer Register
            ("RCR"      , ctypes.c_uint32),      # (Uart Offset: 0x104) Receive Counter Register
            ("TPR"      , ctypes.c_uint32),      # (Uart Offset: 0x108) Transmit Pointer Register
            ("TCR"      , ctypes.c_uint32),      # (Uart Offset: 0x10C) Transmit Counter Register
            ("RNPR"     , ctypes.c_uint32),      # (Uart Offset: 0x110) Receive Next Pointer Register
            ("RNCR"     , ctypes.c_uint32),      # (Uart Offset: 0x114) Receive Next Counter Register
            ("TNPR"     , ctypes.c_uint32),      # (Uart Offset: 0x118) Transmit Next Pointer Register
            ("TNCR"     , ctypes.c_uint32),      # (Uart Offset: 0x11C) Transmit Next Counter Register
            ("PTCR"     , ctypes.c_uint32),      # (Uart Offset: 0x120) Transfer Control Register
            ("PTSR"     , ctypes.c_uint32),      # (Uart Offset: 0x124) Transfer Status Register
        ]

    def __init__(self, ql, label, intn = None):
        super().__init__(ql, label)

        self.uart = self.struct(
            SR = SR.TXRDY
        )
        self.intn = intn

    @QlPeripheral.monitor()
    def read(self, offset: int, size: int) -> int:
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.uart) + offset, size)
        return int.from_bytes(buf.raw, byteorder='little')

    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):      
        if offset == self.struct.THR.offset:
            self.send_to_user(value)

        data = (value).to_bytes(size, byteorder='little')
        ctypes.memmove(ctypes.addressof(self.uart) + offset, data, size)
