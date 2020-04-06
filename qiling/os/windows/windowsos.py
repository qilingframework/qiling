#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 


from unicorn.x86_const import *

from qiling.const import *
from qiling.arch.x86_const import *

class QlWindowsOSManager:
    
    def __init__(self, ql):
        self.ql = ql
        self.user_defined_api = {}
        
        if self.ql.arch == QL_X86:
            self.STRUCTERS_LAST_ADDR = FS_SEGMENT_ADDR
            self.DEFAULT_IMAGE_BASE = 0x400000
            self.HEAP_BASE_ADDR = 0x5000000
            self.HEAP_SIZE = 0x5000000
            self.DLL_BASE_ADDR = 0x10000000
        elif self.ql.arch == QL_X8664:
            self.STRUCTERS_LAST_ADDR = GS_SEGMENT_ADDR 
            self.DEFAULT_IMAGE_BASE = 0x400000
            self.HEAP_BASE_ADDR = 0x500000000
            self.HEAP_SIZE = 0x5000000
            self.DLL_BASE_ADDR = 0x7ffff0000000
            
        self.PE_IMAGE_BASE = 0
        self.PE_IMAGE_SIZE = 0
        self.DLL_SIZE = 0
        self.DLL_LAST_ADDR = self.DLL_BASE_ADDR
        self.PE_RUN = True
        self.last_error = 0
