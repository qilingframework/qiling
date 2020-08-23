#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from unicorn import *
from unicorn.arm_const import *

from qiling.const import *
from .arch import QlArch
from .arm_const import *

class QlArchARM(QlArch):
    def __init__(self, ql):
        super(QlArchARM, self).__init__(ql)
        register_mappings = [
            reg_map
        ]

        for reg_maper in register_mappings:
            self.ql.reg.expand_mapping(reg_maper)

        self.ql.reg.create_reverse_mapping()

        self.ql.reg.register_sp(reg_map["sp"])
        self.ql.reg.register_pc(reg_map["pc"])
        self.arm_get_tls_addr = 0xFFFF0FE0

    def stack_push(self, value):
        self.ql.reg.sp -= 4
        self.ql.mem.write(self.ql.reg.sp, self.ql.pack32(value))
        return self.ql.reg.sp


    def stack_pop(self):
        data = self.ql.unpack32(self.ql.mem.read(self.ql.reg.sp, 4))
        self.ql.reg.sp += 4
        return data


    def stack_read(self, offset):
        return self.ql.unpack32(self.ql.mem.read(self.ql.reg.sp + offset, 4))


    def stack_write(self, offset, data):
        return self.ql.mem.write(self.ql.reg.sp + offset, self.ql.pack32(data))


    # get initialized unicorn engine
    def get_init_uc(self):
        if self.ql.archendian == QL_ENDIAN.EB:
            uc = Uc(UC_ARCH_ARM, UC_MODE_ARM + UC_MODE_BIG_ENDIAN)
        elif self.ql.archtype == QL_ARCH.ARM_THUMB:
            uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        elif self.ql.archtype == QL_ARCH.ARM:
            uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        else:
            uc = None
        return uc


    # get PC
    def get_pc(self):
        mode = self.ql.arch.check_thumb()
        if mode == UC_MODE_THUMB:
            append = 1
        else:
            append = 0
            
        return self.ql.reg.pc + append


    def enable_vfp(self):
        self.ql.reg.c1_c0_2 = self.ql.reg.c1_c0_2 | (0xf << 20)
        if self.ql.archendian == QL_ENDIAN.EB:
            self.ql.reg.fpexc = 0x40000000
            #self.ql.reg.fpexc = 0x00000040
        else:
            self.ql.reg.fpexc = 0x40000000
        self.ql.dprint(D_INFO, "[+] Enable ARM VFP")


    def check_thumb(self):
        reg_cpsr = self.ql.reg.cpsr
        if self.ql.archendian == QL_ENDIAN.EB:
            reg_cpsr_v = 0b100000
            # reg_cpsr_v = 0b000000
        else:
            reg_cpsr_v = 0b100000

        mode = UC_MODE_ARM
        if (reg_cpsr & reg_cpsr_v) != 0:
            mode = UC_MODE_THUMB
            self.ql.dprint(D_INFO, "[+] Enable ARM THUMB")
        return mode
