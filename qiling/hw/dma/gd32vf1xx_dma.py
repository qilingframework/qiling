#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


import ctypes

from qiling.hw.peripheral import QlPeripheral


class GD32VF1xxDma(QlPeripheral):
    class Type(ctypes.Structure):
        """ DMA controller 
        """

        _fields_ = [
            ("INTF"    , ctypes.c_uint32), # Address offset: 0x0, Interrupt flag register
            ("INTC"    , ctypes.c_uint32), # Address offset: 0x04, Interrupt flag clear register
            ("CH0CTL"  , ctypes.c_uint32), # Address offset: 0x08, Channel 0 control register
            ("CH0CNT"  , ctypes.c_uint32), # Address offset: 0x0C, Channel 0 counter register
            ("CH0PADDR", ctypes.c_uint32), # Address offset: 0x10, Channel 0 peripheral base address register
            ("CH0MADDR", ctypes.c_uint32), # Address offset: 0x14, Channel 0 memory base address register
            ("CH1CTL"  , ctypes.c_uint32), # Address offset: 0x1C, Channel 1 control register
            ("CH1CNT"  , ctypes.c_uint32), # Address offset: 0x20, Channel 1 counter register
            ("CH1PADDR", ctypes.c_uint32), # Address offset: 0x24, Channel 1 peripheral base address register
            ("CH1MADDR", ctypes.c_uint32), # Address offset: 0x28, Channel 1 memory base address register
            ("CH2CTL"  , ctypes.c_uint32), # Address offset: 0x30, Channel 2 control register
            ("CH2CNT"  , ctypes.c_uint32), # Address offset: 0x34, Channel 2 counter register
            ("CH2PADDR", ctypes.c_uint32), # Address offset: 0x38, Channel 2 peripheral base address register
            ("CH2MADDR", ctypes.c_uint32), # Address offset: 0x3C, Channel 2 memory base address register
            ("CH3CTL"  , ctypes.c_uint32), # Address offset: 0x44, Channel 3 control register
            ("CH3CNT"  , ctypes.c_uint32), # Address offset: 0x48, Channel 3 counter register
            ("CH3PADDR", ctypes.c_uint32), # Address offset: 0x4C, Channel 3 peripheral base address register
            ("CH3MADDR", ctypes.c_uint32), # Address offset: 0x50, Channel 3 memory base address register
            ("CH4CTL"  , ctypes.c_uint32), # Address offset: 0x58, Channel 4 control register
            ("CH4CNT"  , ctypes.c_uint32), # Address offset: 0x5C, Channel 4 counter register
            ("CH4PADDR", ctypes.c_uint32), # Address offset: 0x60, Channel 4 peripheral base address register
            ("CH4MADDR", ctypes.c_uint32), # Address offset: 0x64, Channel 4 memory base address register
            ("CH5CTL"  , ctypes.c_uint32), # Address offset: 0x6C, Channel 5 control register
            ("CH5CNT"  , ctypes.c_uint32), # Address offset: 0x70, Channel 5 counter register
            ("CH5PADDR", ctypes.c_uint32), # Address offset: 0x74, Channel 5 peripheral base address register
            ("CH5MADDR", ctypes.c_uint32), # Address offset: 0x78, Channel 5 memory base address register
            ("CH6CTL"  , ctypes.c_uint32), # Address offset: 0x80, Channel 6 control register
            ("CH6CNT"  , ctypes.c_uint32), # Address offset: 0x84, Channel 6 counter register
            ("CH6PADDR", ctypes.c_uint32), # Address offset: 0x88, Channel 6 peripheral base address register
            ("CH6MADDR", ctypes.c_uint32), # Address offset: 0x8C, Channel 6 memory base address register
        ]

    def __init__(self, ql, label):
        super().__init__(ql, label)

        self.dma = self.struct(
            INTF     =  0x00000000,
            INTC     =  0x00000000,
            CH0CTL   =  0x00000000,
            CH0CNT   =  0x00000000,
            CH0PADDR =  0x00000000,
            CH0MADDR =  0x00000000,
            CH1CTL   =  0x00000000,
            CH1CNT   =  0x00000000,
            CH1PADDR =  0x00000000,
            CH1MADDR =  0x00000000,
            CH2CTL   =  0x00000000,
            CH2CNT   =  0x00000000,
            CH2PADDR =  0x00000000,
            CH2MADDR =  0x00000000,
            CH3CTL   =  0x00000000,
            CH3CNT   =  0x00000000,
            CH3PADDR =  0x00000000,
            CH3MADDR =  0x00000000,
            CH4CTL   =  0x00000000,
            CH4CNT   =  0x00000000,
            CH4PADDR =  0x00000000,
            CH4MADDR =  0x00000000,
            CH5CTL   =  0x00000000,
            CH5CNT   =  0x00000000,
            CH5PADDR =  0x00000000,
            CH5MADDR =  0x00000000,
            CH6CTL   =  0x00000000,
            CH6CNT   =  0x00000000,
            CH6PADDR =  0x00000000,
            CH6MADDR =  0x00000000,
        )

