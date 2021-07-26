#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn import *

from qiling.const import *
from qiling.dev.peripheral.systick_timer import SysTickTimer
from qiling.dev.mcu.exceptions.nvic import NVIC

from .arm import QlArchARM

class QlArchCORTEX_M(QlArchARM):
    def __init__(self, ql):
        super().__init__(ql)

        ## Core Peripherals
        self.nvic = NVIC(self.ql)
        self.systick = SysTickTimer(ql)

        ## Memory Model
        self.BOOT = [0, 0]
        self.boot_space = 0
        
        ## load from profile
        self.mapinfo = {}
        self.perip_region = {}
        self.peripherals = [
            self.nvic,
            self.systick,
        ]

        def hook_perip_mem_write(ql, access, addr, size, value):
            perip = self.search_peripheral(addr, addr+size)
            if perip:
                base = self.perip_region[perip.name][0][0]
                perip.write(addr - base, size, value)
            else:            
                ql.log.warning('Write non-mapped peripheral (0x%08x)' % (addr))
        
        def hook_perip_mem_read(ql, access, addr, size, value):
            perip = self.search_peripheral(addr, addr+size)
            if perip:
                base = self.perip_region[perip.name][0][0]
                perip.read(addr - base, size)
            else:            
                ql.log.warning('Read  non-mapped peripheral (0x%08x)' % (addr))

        self.perip_read_hook = hook_perip_mem_read
        self.perip_write_hook = hook_perip_mem_write        

    def search_peripheral(self, begin, end):
        def check_bound(lbound, rbound):
            return lbound <= begin and end <= rbound
        
        for perip in self.peripherals:
            for lbound, rbound in self.perip_region[perip.name]:
                if check_bound(lbound, rbound):
                    return perip

    def get_init_uc(self):
        return Uc(UC_ARCH_ARM, UC_MODE_ARM + UC_MODE_MCLASS)

    def step(self):
        self.nvic.interrupt()
        self.ql.emu_start(self.get_pc(), 0, count=1)
        for perip in self.peripherals:
            perip.step()

    def run(self, count=-1):        
        while count != 0:
            self.step()
            count -= 1

    def check_thumb(self):
        return UC_MODE_THUMB
