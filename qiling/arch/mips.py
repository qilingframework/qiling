#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from unicorn import *
from unicorn.mips_const import *

from qiling.const import *
from .arch import QlArch
from .mips_const import *


class QlArchMIPS(QlArch):
    def __init__(self, ql):
        super(QlArchMIPS, self).__init__(ql)

        register_mappings = [
            reg_map, reg_map_afpr128
        ]

        for reg_maper in register_mappings:
            self.ql.reg.expand_mapping(reg_maper)        

        self.ql.reg.create_reverse_mapping()

        self.ql.reg.register_sp(reg_map["sp"])
        self.ql.reg.register_pc(reg_map["pc"])

    def stack_push(self, value):
        self.ql.reg.sp -= 4
        self.ql.mem.write(self.ql.reg.sp, self.ql.pack32(value))
        return self.ql.reg.sp


    def stack_pop(self):
        data = data = self.ql.unpack32(self.ql.mem.read(self.ql.reg.sp, 4))
        self.ql.reg.sp += 4
        return data
        

    def stack_read(self, offset):
        return self.ql.unpack32(self.ql.mem.read(self.ql.reg.sp + offset, 4))


    def stack_write(self, offset, data):
        return self.ql.mem.write(self.ql.reg.sp + offset, self.ql.pack32(data))

    # get initialized unicorn engine
    def get_init_uc(self):
        if self.ql.archtype== QL_ARCH.MIPS:
            if self.ql.archendian == QL_ENDIAN.EB:
                uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN)
            else:
                uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)
        return uc
