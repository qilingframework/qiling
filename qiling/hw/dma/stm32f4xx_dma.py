#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
from qiling.hw.peripheral import QlPeripheral
from qiling.hw.const.stm32f4xx_dma import DMA, DMA_SxCR

class Stream(ctypes.Structure):
    _fields_ = [
        ('CR'  , ctypes.c_uint32),  # DMA stream x configuration register
        ('NDTR', ctypes.c_uint32),  # DMA stream x number of data register
        ('PAR' , ctypes.c_uint32),  # DMA stream x peripheral address register
        ('M0AR', ctypes.c_uint32),  # DMA stream x memory 0 address register
        ('M1AR', ctypes.c_uint32),  # DMA stream x memory 1 address register
        ('FCR' , ctypes.c_uint32),  # DMA stream x FIFO control register
    ]

    def enable(self):
        return self.CR & DMA_SxCR.EN

    def transfer_direction(self):
        return self.CR & DMA_SxCR.DIR

    def transfer_peripheral_size(self):
        PSIZE = self.CR & DMA_SxCR.PSIZE
        if PSIZE == DMA.PDATAALIGN_BYTE:
            return 1
        if PSIZE == DMA.PDATAALIGN_HALFWORD:
            return 2
        if PSIZE == DMA.PDATAALIGN_WORD:
            return 4

    def transfer_memory_size(self):
        MSIZE = self.CR & DMA_SxCR.MSIZE
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
        
        src, dst = (self.M0AR, self.PAR) if dir_flag else (self.PAR, self.M0AR)
        src_size, dst_size = (msize, psize) if dir_flag else (psize, msize)

        data = bytes(mem.read(src, src_size)).ljust(dst_size)[:dst_size]
        mem.write(dst, data)

        self.NDTR -= 1
        if self.CR & DMA_SxCR.MINC:
            self.M0AR += msize
        if self.CR & DMA_SxCR.PINC:
            self.PAR  += psize

        if self.NDTR == 0:
            self.CR &= ~DMA_SxCR.EN
            return True
        
class STM32F4xxDma(QlPeripheral):
    class Type(ctypes.Structure):
        """ the structure available in :
			stm32f413xx.h
			stm32f407xx.h
			stm32f469xx.h
			stm32f446xx.h
			stm32f427xx.h
			stm32f401xc.h
			stm32f415xx.h
			stm32f412cx.h
			stm32f410rx.h
			stm32f410tx.h
			stm32f439xx.h
			stm32f412vx.h
			stm32f417xx.h
			stm32f479xx.h
			stm32f429xx.h
			stm32f412rx.h
			stm32f423xx.h
			stm32f437xx.h
			stm32f412zx.h
			stm32f401xe.h
			stm32f410cx.h
			stm32f405xx.h
			stm32f411xe.h 
		"""

        _fields_ = [
			('LISR' , ctypes.c_uint32),  # DMA low interrupt status register,      Address offset: 0x00
			('HISR' , ctypes.c_uint32),  # DMA high interrupt status register,     Address offset: 0x04
			('LIFCR', ctypes.c_uint32),  # DMA low interrupt flag clear register,  Address offset: 0x08
			('HIFCR', ctypes.c_uint32),  # DMA high interrupt flag clear register, Address offset: 0x0C
            ('stream', Stream * 8),
        ]

    def __init__(
            self, ql, label, 
            stream0_intn=None,
            stream1_intn=None,
            stream2_intn=None,
            stream3_intn=None,
            stream4_intn=None,
            stream5_intn=None,
            stream6_intn=None,
            stream7_intn=None
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

    @QlPeripheral.monitor(width=15)
    def read(self, offset: int, size: int) -> int:        
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.dma) + offset, size)
        return int.from_bytes(buf.raw, byteorder='little')

    @QlPeripheral.monitor(width=15)
    def write(self, offset: int, size: int, value: int):        
        if offset == self.struct.LIFCR.offset:
            self.dma.LISR &= ~value

        elif offset == self.struct.HIFCR.offset:
            self.dma.HISR &= ~value

        elif offset > self.struct.HIFCR.offset:
            data = (value).to_bytes(size, byteorder='little')
            ctypes.memmove(ctypes.addressof(self.dma) + offset, data, size)

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


    def transfer_complete(self, id):
        tc_bits = [5, 11, 21, 27]
        if id > 4:
            self.dma.HISR |= 1 << tc_bits[id - 4]
        else:
            self.dma.LISR |= 1 << tc_bits[id]

        if self.intn[id] is not None:
            self.ql.hw.nvic.set_pending(self.intn[id])

    def step(self):
        for id, stream in enumerate(self.dma.stream):
            if not stream.enable():
                continue
                                    
            if stream.step(self.ql.mem):
                self.transfer_complete(id)                
