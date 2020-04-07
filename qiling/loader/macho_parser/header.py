#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from .utils import *
from .const import *
from struct import unpack

class Header:

    def __init__(self, data):
        self.binary = data
            

class BinaryHeader(Header):

    def __init__(self, data):
        super().__init__(data)
        FR = FileReader(data)
        self.magic          = unpack("<L", FR.read(4))[0]
        self.cpu_type       = unpack("<L", FR.read(4))[0]
        self.cpu_subtype    = unpack("<L", FR.read(4))[0]
        self.file_type      = unpack("<L", FR.read(4))[0]
        self.lc_num         = unpack("<L", FR.read(4))[0]
        self.lc_size        = unpack("<L", FR.read(4))[0]
        self.flags          = unpack("<L", FR.read(4))[0]
        
        if self.magic == MAGIC_64:
            self.reserved = unpack("<L", FR.read(4))[0]
        self.header_size = FR.offset

    #def __str__(self):
        # return ("magic : 0x%X, cputype: 0x%X, subType: 0x%X, FileType: 0x%X, lc num: 0x%X, lc size: 0x%X, flags: 0x%X" % (self.magic, 
        #     self.cpu_type, self.cpu_subtype, self.file_type, self.lc_num, self.lc_size, self.flags))


class FatHeader(Header):

    def __init__(self, data):
        super().__init__(data)
        FR = FileReader(data)
        FR.setOffset(4)
        self.binarys = []
        self.arch_num = unpack(">L", FR.read(4))[0]
        for i in range(self.arch_num):
            FI = FatInfo(FR.read(4 * 5))
            self.binarys.append(FI)

    def getBinary(self, arch):

        for item in self.binarys:
            if item.cpu_type == CPU_TYPE_X8664:
                return item
            elif item.cpu_type == CPU_TYPE_ARM64:
                return item 
        return None

class FatInfo:
    def __init__(self, data):
        FR = FileReader(data)
        self.cpu_type       = unpack(">L", FR.read(4))[0]
        self.cpu_subtype    = unpack(">L", FR.read(4))[0]
        self.offset         = unpack(">L", FR.read(4))[0]
        self.size           = unpack(">L", FR.read(4))[0]
        self.align          = 2 ** unpack(">L", FR.read(4))[0]
    
    # def __str__(self):
    #     return ("CPU 0x%X, CPU subtype 0x%X, offset 0x%X, size 0x%X, align %d" %(
    #         self.cpu_type, self.cpu_subtype, self.offset, self.size, self.align
    #     ))