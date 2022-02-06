#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

from qiling.hw.peripheral import QlPeripheral
from qiling.hw.const.stm32f1xx_dma import DMA_CR, DMA


class Stream(ctypes.Structure):
    _fields_ = [
        ("CR"  , ctypes.c_uint32),
        ("NDTR", ctypes.c_uint32),
        ("PAR" , ctypes.c_uint32),
        ("MAR" , ctypes.c_uint32),
        ("RESEVERED" , ctypes.c_uint32),
    ]

    def enable(self):
        return self.CR & DMA_CR.EN

    def transfer_direction(self):
        return self.CR & DMA_CR.DIR

    def transfer_peripheral_size(self):
        PSIZE = self.CR & DMA_CR.PSIZE
        if PSIZE == DMA.PDATAALIGN_BYTE:
            return 1
        if PSIZE == DMA.PDATAALIGN_HALFWORD:
            return 2
        if PSIZE == DMA.PDATAALIGN_WORD:
            return 4

    def transfer_memory_size(self):
        MSIZE = self.CR & DMA_CR.MSIZE
        if MSIZE == DMA.MDATAALIGN_BYTE:
            return 1
        if MSIZE == DMA.MDATAALIGN_HALFWORD:
            return 2
        if MSIZE == DMA.MDATAALIGN_WORD:
            return 4

    def step(self, mem):
        if self.NDTR == 0:
            return

        dir_flag = self.transfer_direction() == DMA.MEMORY_TO_PERIPH 
        
        psize = self.transfer_peripheral_size()
        msize = self.transfer_memory_size()

        src, dst = (self.MAR, self.PAR) if dir_flag else (self.PAR, self.MAR)
        src_size, dst_size = (msize, psize) if dir_flag else (psize, msize)

        data = bytes(mem.read(src, src_size)).ljust(dst_size)[:dst_size]
        mem.write(dst, data)
        
        self.NDTR -= 1
        if self.CR & DMA_CR.MINC:
            self.MAR += msize
        if self.CR & DMA_CR.PINC:
            self.PAR += psize

        if self.NDTR == 0:
            self.CR &= ~DMA_CR.EN
            return True


class STM32F1xxDma(QlPeripheral):
    class Type(ctypes.Structure):
        """ the structure available in :
                stm32f100xb
                stm32f100xe
                stm32f101xb
                stm32f101xe
                stm32f101xg
                stm32f102xb
                stm32f103xb
                stm32f103xe
                stm32f103xg
                stm32f105xc
                stm32f107xc
        """

        _fields_ = [
            ("ISR" , ctypes.c_uint32),
            ("IFCR", ctypes.c_uint32),
            ("stream", Stream * 8),
        ]

    def __init__(self, ql, label,
        stream0_intn=None,
        stream1_intn=None,
        stream2_intn=None,
        stream3_intn=None,
        stream4_intn=None,
        stream5_intn=None,
        stream6_intn=None,
        stream7_intn=None,
    ):
        super().__init__(ql, label)
        
        self.dma = self.struct()
        
        self.intn = [
            stream0_intn,
            stream1_intn,
            stream2_intn,
            stream3_intn,
            stream4_intn,
            stream5_intn,
            stream6_intn,
            stream7_intn,
        ]

    def find_field(self, offset: int, size: int) -> str:
        field_list = []
        if offset < self.struct.stream.offset:
            field_list.append(super().find_field(offset, min(size, self.struct.stream.offset - offset)))
        
        if offset >= self.struct.stream.offset:
            for i in range(8):
                prefix_offset = self.struct.stream.offset + ctypes.sizeof(Stream) * i
                
                for name, _ in Stream._fields_:
                    field = getattr(Stream, name)
                    field_offset = field.offset + prefix_offset

                    lbound = max(0, offset - field_offset)
                    ubound = min(offset + size  - field_offset, field.size)
                    if lbound < ubound:
                        if lbound == 0 and ubound == field.size:
                            field_list.append(f'stream[{i}].{name}')
                        else:
                            field_list.append(f'stream[{i}].{name}[{lbound}:{ubound}]')
                
        return ','.join(field_list)

    @QlPeripheral.monitor(width=15)
    def read(self, offset: int, size: int) -> int:        
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.dma) + offset, size)
        return int.from_bytes(buf.raw, byteorder='little')

    @QlPeripheral.monitor(width=15)
    def write(self, offset: int, size: int, value: int):
        if offset == self.struct.ISR.offset:
            return

        elif offset == self.struct.IFCR.offset:
            self.dma.ISR &= ~value

        else:
            data = (value).to_bytes(size, byteorder='little')
            ctypes.memmove(ctypes.addressof(self.dma) + offset, data, size)

    def transfer_complete(self, id):
        tc_bits = [1, 5, 9, 13, 17, 21, 25]
        self.dma.ISR |= 1 << tc_bits[id]

        if self.intn[id] is not None:
            self.ql.hw.nvic.set_pending(self.intn[id])

    def step(self):
        for id, stream in enumerate(self.dma.stream):
            if not stream.enable():
                continue
                                    
            if stream.step(self.ql.mem):
                self.transfer_complete(id)
