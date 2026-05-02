#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral
from qiling.hw.const.stm32f4xx_eth import ETH_DMABMR, ETH_MACMIIAR


class STM32F4xxEth(QlPeripheral):
    class Type(ctypes.Structure):
        """ the structure available in :
                stm32f407xx
                stm32f417xx
                stm32f427xx
                stm32f429xx
                stm32f437xx
                stm32f439xx
                stm32f469xx
                stm32f479xx
        """

        _fields_ = [
            ("MACCR"      , ctypes.c_uint32),
            ("MACFFR"     , ctypes.c_uint32),
            ("MACHTHR"    , ctypes.c_uint32),
            ("MACHTLR"    , ctypes.c_uint32),
            ("MACMIIAR"   , ctypes.c_uint32),
            ("MACMIIDR"   , ctypes.c_uint32),
            ("MACFCR"     , ctypes.c_uint32),
            ("MACVLANTR"  , ctypes.c_uint32),
            ("RESERVED0"  , ctypes.c_uint32 * 2),
            ("MACRWUFFR"  , ctypes.c_uint32),
            ("MACPMTCSR"  , ctypes.c_uint32),
            ("RESERVED1"  , ctypes.c_uint32),
            ("MACDBGR"    , ctypes.c_uint32),
            ("MACSR"      , ctypes.c_uint32),
            ("MACIMR"     , ctypes.c_uint32),
            ("MACA0HR"    , ctypes.c_uint32),
            ("MACA0LR"    , ctypes.c_uint32),
            ("MACA1HR"    , ctypes.c_uint32),
            ("MACA1LR"    , ctypes.c_uint32),
            ("MACA2HR"    , ctypes.c_uint32),
            ("MACA2LR"    , ctypes.c_uint32),
            ("MACA3HR"    , ctypes.c_uint32),
            ("MACA3LR"    , ctypes.c_uint32),
            ("RESERVED2"  , ctypes.c_uint32 * 40),
            ("MMCCR"      , ctypes.c_uint32),
            ("MMCRIR"     , ctypes.c_uint32),
            ("MMCTIR"     , ctypes.c_uint32),
            ("MMCRIMR"    , ctypes.c_uint32),
            ("MMCTIMR"    , ctypes.c_uint32),
            ("RESERVED3"  , ctypes.c_uint32 * 14),
            ("MMCTGFSCCR" , ctypes.c_uint32),
            ("MMCTGFMSCCR", ctypes.c_uint32),
            ("RESERVED4"  , ctypes.c_uint32 * 5),
            ("MMCTGFCR"   , ctypes.c_uint32),
            ("RESERVED5"  , ctypes.c_uint32 * 10),
            ("MMCRFCECR"  , ctypes.c_uint32),
            ("MMCRFAECR"  , ctypes.c_uint32),
            ("RESERVED6"  , ctypes.c_uint32 * 10),
            ("MMCRGUFCR"  , ctypes.c_uint32),
            ("RESERVED7"  , ctypes.c_uint32 * 334),
            ("PTPTSCR"    , ctypes.c_uint32),
            ("PTPSSIR"    , ctypes.c_uint32),
            ("PTPTSHR"    , ctypes.c_uint32),
            ("PTPTSLR"    , ctypes.c_uint32),
            ("PTPTSHUR"   , ctypes.c_uint32),
            ("PTPTSLUR"   , ctypes.c_uint32),
            ("PTPTSAR"    , ctypes.c_uint32),
            ("PTPTTHR"    , ctypes.c_uint32),
            ("PTPTTLR"    , ctypes.c_uint32),
            ("RESERVED8"  , ctypes.c_uint32),
            ("PTPTSSR"    , ctypes.c_uint32),
            ("RESERVED9"  , ctypes.c_uint32 * 565),
            ("DMABMR"     , ctypes.c_uint32),
            ("DMATPDR"    , ctypes.c_uint32),
            ("DMARPDR"    , ctypes.c_uint32),
            ("DMARDLAR"   , ctypes.c_uint32),
            ("DMATDLAR"   , ctypes.c_uint32),
            ("DMASR"      , ctypes.c_uint32),
            ("DMAOMR"     , ctypes.c_uint32),
            ("DMAIER"     , ctypes.c_uint32),
            ("DMAMFBOCR"  , ctypes.c_uint32),
            ("DMARSWTR"   , ctypes.c_uint32),
            ("RESERVED10" , ctypes.c_uint32 * 8),
            ("DMACHTDR"   , ctypes.c_uint32),
            ("DMACHRDR"   , ctypes.c_uint32),
            ("DMACHTBAR"  , ctypes.c_uint32),
            ("DMACHRBAR"  , ctypes.c_uint32),
        ]

    def __init__(self, ql, label, intn=None, wkup_intn=None):
        super().__init__(ql, label)
                
        self.instance = self.struct()

        self.intn = intn
        self.wkup_intn = wkup_intn

    @QlPeripheral.monitor()
    def read(self, offset: int, size: int) -> int:
        return self.raw_read(offset, size)

    
    @QlPeripheral.monitor()
    def write(self, offset: int, size: int, value: int):
        self.raw_write(offset, size, value)

        if offset == self.struct.DMABMR.offset:
            if value & ETH_DMABMR.SR:
                self.instance.DMABMR &= ~ETH_DMABMR.SR
        
        if offset == self.struct.MACMIIAR.offset:
            if value & ETH_MACMIIAR.MB:
                self.instance.MACMIIAR &= ~ETH_MACMIIAR.MB
                self.instance.MACMIIDR = 0xffff
