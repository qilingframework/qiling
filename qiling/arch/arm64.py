#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from unicorn import *
from unicorn.arm64_const import *

from qiling.const import *
from .arch import QlArch
from .arm64_const import *

class QlArchARM64(QlArch):
    def __init__(self, ql):
        super(QlArchARM64, self).__init__(ql)

        register_mappings = [
            reg_map
        ]

        for reg_maper in register_mappings:
            self.ql.reg.expand_mapping(reg_maper)            

        self.ql.reg.create_reverse_mapping()

        self.ql.reg.register_sp(reg_map["sp"])
        self.ql.reg.register_pc(reg_map["pc"])


    def stack_push(self, value):
        self.ql.reg.sp -= 8
        self.ql.mem.write(self.ql.reg.sp, self.ql.pack64(value))
        return self.ql.reg.sp


    def stack_pop(self):
        data = self.ql.unpack64(self.ql.mem.read(self.ql.reg.sp, 8))
        self.ql.reg.sp += 8
        return data


    def stack_read(self, offset):
        return self.ql.unpack64(self.ql.mem.read(self.ql.reg.sp + offset, 8))


    def stack_write(self, offset, data):
        return self.ql.mem.write(self.ql.reg.sp + offset, self.ql.pack64(data))


    # get initialized unicorn engine
    def get_init_uc(self):
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)   
        return uc


    def enable_vfp(self):
        self.ql.reg.cpacr_el1 = self.ql.reg.cpacr_el1 | 0x300000
