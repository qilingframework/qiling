#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from qiling.const import *
from qiling.arch.x86_const import *

class QlLoader:
    def __init__(self, ql):

        self.ql = ql
        if self.ql.archtype== QL_X86:
            self.STRUCTERS_LAST_ADDR = FS_SEGMENT_ADDR
            self.DEFAULT_IMAGE_BASE = 0x400000
            self.DLL_BASE_ADDR = 0x10000000
            self.HEAP_BASE_ADDR = 0x5000000
            self.HEAP_SIZE = 0x5000000
            
        elif self.ql.archtype== QL_X8664:
            self.STRUCTERS_LAST_ADDR = GS_SEGMENT_ADDR 
            self.DEFAULT_IMAGE_BASE = 0x400000
            self.DLL_BASE_ADDR = 0x7ffff0000000
            self.HEAP_BASE_ADDR = 0x500000000
            self.HEAP_SIZE = 0x5000000
            
        self.cmdline = b"D:\\" + bytes(self.ql.path.replace("/", "\\"), "utf-8") + b"\x00"             
        self.dlls = {}
        self.import_symbols = {}
        self.import_address_table = {}
        self.ldr_list = []
        self.PE_IMAGE_BASE = 0
        self.PE_IMAGE_SIZE = 0
        self.DLL_SIZE = 0
        self.DLL_LAST_ADDR = self.DLL_BASE_ADDR