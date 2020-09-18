#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
from qiling import *


class QlDebugger():
    def __init__(self, ql:Qiling):
        self.ql = ql

    def dbg_start(self):
        pass

    def dbg_run(self, begin_addr=None, end_addr=None):
        self.ql.emu_start(begin=begin_addr, end=end_addr)
    
    def dbg_step(self):
        pass

    def dbg_continue(self):
        pass

    def dbg_set_breakpoint(self):
        pass

    def addr_to_str(self, addr, short=False, endian="big"):
        if self.ql.archbit == 64 and short == False:
            addr = (hex(int.from_bytes(self.ql.pack64(addr), byteorder=endian)))
            addr = '{:0>16}'.format(addr[2:])
        elif self.ql.archbit == 32 or short == True:
            addr = (hex(int.from_bytes(self.ql.pack32(addr), byteorder=endian)))
            addr = ('{:0>8}'.format(addr[2:]))
        elif self.ql.archbit == 16 or short == True:
            addr = (hex(int.from_bytes(self.ql.pack32(addr), byteorder=endian)))
            addr = ('{:0>8}'.format(addr[2:]))            
        addr = str(addr)    
        return addr

