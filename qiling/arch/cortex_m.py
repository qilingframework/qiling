#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn import *
from unicorn.arm_const import *

from capstone import *

from qiling.const import *
from qiling.mcu.stm32.exceptions.manager import ExceptionManager
from .arm import QlArchARM

class QlArchCORTEX_M(QlArchARM):
    def __init__(self, ql):
        super().__init__(ql)

        self.md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)

        ## Exception Model
        self.emgr = ExceptionManager(self)

        ## Memory Model
        self.BOOT = [0, 0]
        self.boot_space = 0
        self.mapinfo = {
            'sram'      : (0x20000000, 0x20020000),
            'system'    : (0x1FFF0000, 0x1FFF7800),            
            'flash'     : (0x08000000, 0x08080000),             
            'peripheral': (0x40000000, 0x40100000),
            'core_perip': (0xE0000000, 0xE0100000),
        }

    def get_init_uc(self):
        return Uc(UC_ARCH_ARM, UC_MODE_ARM + UC_MODE_MCLASS)

    def setup(self):        
        def hook_code(mu, address, size, user_data):     
            code = mu.mem_read(address, size)
            for i in self.md.disasm(code, address):
                self.ql.log.info('%s %s %s' % (hex(i.address), i.mnemonic, i.op_str))

        self.ql.uc.hook_add(UC_HOOK_CODE, hook_code)

        for begin, end in self.mapinfo.values():
            self.mem.map(begin, end - begin)
        
    def flash(self):
        self.ql.loader.run()

    def reset(self):
        if self.BOOT[0] == 0:
            self.boot_space = self.mapinfo['flash'][0]
        elif self.BOOT[1] == 0:
            self.boot_space = self.mapinfo['system'][0]
        elif self.BOOT[1] == 1:
            self.boot_space = self.mapinfo['sram'][0]

        self.reg.write('lr', 0xffffffff)
        self.reg.write('msp', self.mem.read_ptr(self.boot_space))
        self.reg.write('pc', self.mem.read_ptr(self.boot_space + 0x4))
        
    def step(self):
        self.emgr.interrupt()
        self.ql.emu_start(self.get_pc() | 1, 0, count=1)

    def run(self, count=-1):        
        while count != 0:
            self.step()
            count -= 1

    @property
    def reg(self):
        return self.ql.reg
    
    @property
    def mem(self):
        return self.ql.mem