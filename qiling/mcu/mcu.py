#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import struct

from unicorn import *
from unicorn import *
from unicorn.arm_const import *

class QlMcu:
    def __init__(self, ql):
        self.ql = ql        

        self.disassembler = self.ql.arch.create_disassembler()
        def hook_code(mu, address, size, user_data):     
            code = mu.mem_read(address, size)
            for i in self.disassembler.disasm(code, address):
                print(hex(i.address), i.mnemonic, i.op_str)

        def hook_mem(uc, access, address, size, value, user_data):    
            if access == UC_MEM_WRITE:
                print(f'[W] {hex(address)[2:].zfill(8)}:{hex(size)[2:]} = {hex(value)}\t')
            if access == UC_MEM_READ:
                print(f'[R] {hex(address)[2:].zfill(8)}:{hex(size)[2:]}')

        self.uc.hook_add(UC_HOOK_CODE, hook_code)
        self.uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem)

        self.BOOT = [0, 0]
        self.boot_space = 0x00000000

        self.memory_mapping = {
            'sram'      : (0x20000000, 0x20020000),
            'system'    : (0x1FFF0000, 0x1FFF7800),            
            'flash'     : (0x08000000, 0x08080000),             
            'peripheral': (0x40000000, 0x40100000),
            'ppb'       : (0xE0000000, 0xE0100000),
        }

    def setup(self):
        for begin, end in self.memory_mapping.values():
            self.mem.map(begin, end - begin)

    def flash(self):
        self.ql.loader.run()

    def reset(self):
        if self.BOOT[0] == 0:
            self.boot_space = self.memory_mapping['flash'][0]
        elif self.BOOT[1] == 0:
            self.boot_space = self.memory_mapping['system'][0]
        elif self.BOOT[1] == 1:
            self.boot_space = self.memory_mapping['sram'][0]

        self.reg.write('lr', 0xffffffff)
        self.reg.write('msp', self.mem.read_ptr(self.boot_space))
        self.reg.write('pc', self.mem.read_ptr(self.boot_space + 0x4))

    def start(self):
        self.reset()
        for _ in range(10000):
            self.uc.emu_start(self.reg.read('pc') | 1, -1, count=1)
            self.uc.mem_write(0x20000028, struct.pack('<I', 
                struct.unpack('<I', self.uc.mem_read(0x20000028, 4))[0]+ 1))
        
    @property
    def uc(self):
        return self.ql.uc

    @property
    def reg(self):
        return self.ql.reg

    @property
    def mem(self):
        return self.ql.mem
