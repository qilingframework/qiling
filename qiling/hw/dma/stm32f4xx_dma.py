#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes
from qiling.hw.peripheral import QlPeripheral

class Stream_Type(ctypes.Structure):
    _fields_ = [
        ('CR'   , ctypes.c_uint32),
        ('NDTR' , ctypes.c_uint32),
        ('PAR'  , ctypes.c_uint32),
        ('M0AR' , ctypes.c_uint32),
        ('M1AR' , ctypes.c_uint32),
        ('FCR'  , ctypes.c_uint32),
    ]

class STM32F4xxDma(QlPeripheral):
    class Type(ctypes.Structure):
        _fields_ = [
            ('LISR'  , ctypes.c_uint32),
            ('HISR'  , ctypes.c_uint32),
            ('LIFCR' , ctypes.c_uint32),
            ('HIFCR' , ctypes.c_uint32),
            ('Stream', Stream_Type * 8),
        ]

    def __init__(self, ql, tag):
        super().__init__(ql, tag)
        
        DMA_Type = type(self).Type
        self.dma = DMA_Type()

    def read(self, offset, size):        
        self.ql.log.warning('DMA read  [0x%08x:%d]' % (offset, size))

        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, ctypes.addressof(self.dma) + offset, size)
        retval = int.from_bytes(buf.raw, byteorder='little')
        return retval

    def write(self, offset, size, value):
        self.ql.log.warning('DMA write [0x%08x:%d] = 0x%08x' % (offset, size, value))
        
        data = (value).to_bytes(size, byteorder='little')
        ctypes.memmove(ctypes.addressof(self.dma) + offset, data, size)
