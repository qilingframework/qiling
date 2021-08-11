#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
from qiling.hw.peripheral import QlPeripheral
from qiling.hw.const.dma import DMA, DMA_CR

class Stream(ctypes.Structure):
    _fields_ = [
        ('CR'   , ctypes.c_uint32),
        ('NDTR' , ctypes.c_uint32), # Number of data items to transfer
        ('PAR'  , ctypes.c_uint32),
        ('M0AR' , ctypes.c_uint32),
        ('M1AR' , ctypes.c_uint32),
        ('FCR'  , ctypes.c_uint32),
    ]

    def enable(self):
        return self.CR & DMA_CR.EN

    def transfer_direction(self):
        return self.CR & DMA_CR.DIR

    def transfer_size(self):
        PSIZE = self.CR & DMA_CR.PSIZE
        if PSIZE == DMA.PDATAALIGN_BYTE:
            return 1
        if PSIZE == DMA.PDATAALIGN_HALFWORD:
            return 2
        if PSIZE == DMA.PDATAALIGN_WORD:
            return 4

    def step(self, mem):
        if self.NDTR == 0:
            return False

        dir = self.transfer_direction()
        if dir == DMA.MEMORY_TO_PERIPH:
            src = self.M0AR
            dst = self.PAR
            size = self.transfer_size()

            mem.write(dst, bytes(mem.read(src, size)))
        
        self.NDTR -= 1
        if self.CR & DMA_CR.MINC:
            self.M0AR += size
        if self.CR & DMA_CR.PINC:
            self.PAR  += size

        return self.NDTR == 0
        

class STM32F4xxDma(QlPeripheral):
    class Type(ctypes.Structure):
        _fields_ = [
            ('LISR'  , ctypes.c_uint32),
            ('HISR'  , ctypes.c_uint32),
            ('LIFCR' , ctypes.c_uint32),
            ('HIFCR' , ctypes.c_uint32),
            ('stream', Stream * 8),
        ]

    def __init__(self, ql, tag, IRQn=None):
        super().__init__(ql, tag)
        
        DMA_Type = type(self).Type
        self.dma = DMA_Type()

        self.LIFCR = DMA_Type.LIFCR.offset
        self.HIFCR = DMA_Type.HIFCR.offset

        self.stream_base = 0x10
        self.stream_size = ctypes.sizeof(Stream)        

        self.IRQn = IRQn

    def stream_index(self, offset):
        return (offset - self.stream_base) // self.stream_size

    def read(self, offset, size):        
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.dma) + offset, size)
        retval = int.from_bytes(buf.raw, byteorder='little')
        return retval

    def write(self, offset, size, value):        
        if offset == self.LIFCR:
            self.dma.LISR &= ~value
        elif offset == self.HIFCR:
            self.dma.HISR &= ~value
        elif offset > self.HIFCR:
            stream_id = self.stream_index(offset)
            self.ql.log.warning('DMA write 0x%08x stream %d at 0x%02x' % (value, stream_id, offset - stream_id * 0x18 - 0x10))

            data = (value).to_bytes(size, byteorder='little')
            ctypes.memmove(ctypes.addressof(self.dma) + offset, data, size)

    def step(self):
        for id, stream in enumerate(self.dma.stream):
            if not stream.enable():
                continue
                                    
            if stream.step(self.ql.mem):
                stream.CR &= ~DMA_CR.EN
                self.ql.hw.intc.set_pending(self.IRQn[id])
