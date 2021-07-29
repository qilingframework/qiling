#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn import *

from qiling.const import *
from qiling.hw.misc.sysctrl import SystemControlBlock

from .arm import QlArchARM

class QlArchCORTEX_M(QlArchARM):
    def __init__(self, ql):
        super().__init__(ql)

        ## Core Hardwares
        self.ql.hw.create_hardware('intc', 'nvic')
        self.ql.hw.create_hardware('timer', 'sys_tick')

        ## Memory Model
        self.BOOT = [0, 0]
        self.boot_space = 0
        
        ## load from profile
        self.mapinfo = {}
        self.perip_region = {}

        def hook_perip_mem_write(ql, access, addr, size, value):
            perip = self.search_peripheral(addr, addr+size)
            if perip:
                base = self.perip_region[perip.tag][0][0]
                perip.write(addr - base, size, value)
            else:            
                ql.log.warning('Write non-mapped peripheral (*0x%08x = 0x%08x)' % (addr, value))
        
        def hook_perip_mem_read(ql, access, addr, size, value):
            perip = self.search_peripheral(addr, addr+size)
            if perip:
                base = self.perip_region[perip.tag][0][0]
                ql.mem.write(addr, perip.read(addr - base, size))
            else:            
                ql.log.warning('Read non-mapped peripheral (0x%08x)' % (addr))

        self.perip_read_hook = hook_perip_mem_read
        self.perip_write_hook = hook_perip_mem_write        

    def search_peripheral(self, begin, end):
        def check_bound(lbound, rbound):
            return lbound <= begin and end <= rbound
        
        for tag, perip in self.ql.hw.items():
            for lbound, rbound in self.perip_region[tag]:
                if check_bound(lbound, rbound):
                    return perip

    def get_init_uc(self):
        return Uc(UC_ARCH_ARM, UC_MODE_ARM + UC_MODE_MCLASS)

    def step(self):
        self.ql.hw.nvic.interrupt()
        self.ql.emu_start(self.get_pc(), 0, count=1)
        for _, hw in self.ql.hw.items():
            hw.step()

    def run(self, count=-1):        
        while count != 0:
            self.step()
            count -= 1

    def check_thumb(self):
        return UC_MODE_THUMB
