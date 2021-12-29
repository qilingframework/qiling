#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


import ctypes

from qiling.hw.peripheral import QlPeripheral


class GD32VF1xxTimer(QlPeripheral):
    class Type(ctypes.Structure):
        """ Advanced-timers 
        """

        _fields_ = [
            ("CTL0"         , ctypes.c_uint16), # Address offset: 0x0, control register 0
            ("CTL1"         , ctypes.c_uint16), # Address offset: 0x04, control register 1
            ("SMCFG"        , ctypes.c_uint16), # Address offset: 0x08, slave mode configuration register
            ("DMAINTEN"     , ctypes.c_uint16), # Address offset: 0x0C, DMA/Interrupt enable register
            ("INTF"         , ctypes.c_uint16), # Address offset: 0x10, Interrupt flag register
            ("SWEVG"        , ctypes.c_uint16), # Address offset: 0x14, Software event generation register
            ("CHCTL0_Output", ctypes.c_uint16), # Address offset: 0x18, Channel control register 0 (output mode)
            ("CHCTL0_Input" , ctypes.c_uint16), # Address offset: 0x18, Channel control register 0 (input mode)
            ("CHCTL1_Output", ctypes.c_uint16), # Address offset: 0x1C, Channel control register 1 (output mode)
            ("CHCTL1_Input" , ctypes.c_uint16), # Address offset: 0x1C, Channel control register 1 (input mode)
            ("CHCTL2"       , ctypes.c_uint16), # Address offset: 0x20, Channel control register 2
            ("CNT"          , ctypes.c_uint16), # Address offset: 0x24, counter
            ("PSC"          , ctypes.c_uint16), # Address offset: 0x28, prescaler
            ("CAR"          , ctypes.c_uint16), # Address offset: 0x2C, Counter auto reload register
            ("CREP"         , ctypes.c_uint16), # Address offset: 0x30, Counter repetition register
            ("CH0CV"        , ctypes.c_uint16), # Address offset: 0x34, Channel 0 capture/compare value register
            ("CH1CV"        , ctypes.c_uint16), # Address offset: 0x38, Channel 1 capture/compare value register
            ("CH2CV"        , ctypes.c_uint16), # Address offset: 0x3C, Channel 2 capture/compare value register
            ("CH3CV"        , ctypes.c_uint16), # Address offset: 0x40, Channel 3 capture/compare value register
            ("CCHP"         , ctypes.c_uint16), # Address offset: 0x44, channel complementary protection register
            ("DMACFG"       , ctypes.c_uint16), # Address offset: 0x48, DMA configuration register
            ("DMATB"        , ctypes.c_uint16), # Address offset: 0x4C, DMA transfer buffer register
        ]

    def __init__(self, ql, label):
        super().__init__(ql, label)

        self.timer = self.struct(
            CTL0          =  0x00000000,
            CTL1          =  0x00000000,
            SMCFG         =  0x00000000,
            DMAINTEN      =  0x00000000,
            INTF          =  0x00000000,
            SWEVG         =  0x00000000,
            CHCTL0_Output =  0x00000000,
            CHCTL0_Input  =  0x00000000,
            CHCTL1_Output =  0x00000000,
            CHCTL1_Input  =  0x00000000,
            CHCTL2        =  0x00000000,
            CNT           =  0x00000000,
            PSC           =  0x00000000,
            CAR           =  0x00000000,
            CREP          =  0x00000000,
            CH0CV         =  0x00000000,
            CH1CV         =  0x00000000,
            CH2CV         =  0x00000000,
            CH3CV         =  0x00000000,
            CCHP          =  0x00000000,
            DMACFG        =  0x00000000,
            DMATB         =  0x00000000,
        )

