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
            uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
            # FIXME: unicorn engine not able to choose ARM or Thumb automatically
            #uc = Uc(UC_ARCH_ARM, UC_MODE_ARM + UC_MODE_BIG_ENDIAN)
        else:
            uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)    
        return uc


    # set PC
    def set_pc(self, value):
        self.ql.reg.pc = value


    # get PC
    def get_pc(self):
        mode = self.ql.arch.check_thumb()
        if mode == UC_MODE_THUMB:
            append = 1
        else:
            append = 0
            
        return self.ql.reg.pc + append


    # set stack pointer
    def set_sp(self, value):
        self.ql.reg.sp = value


    # get stack pointer
    def get_sp(self):
        return self.ql.reg.sp


    # get stack pointer register
    def get_name_sp(self):
        return reg_map["sp"]


    # get pc register pointer
    def get_name_pc(self):
        return reg_map["pc"]


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


    def get_reg_table(self):
        registers_table = []
        adapter = {}
        adapter.update(reg_map)
        registers = {k:v for k, v in adapter.items()}
 
        for reg in registers:
            registers_table += [reg]
        
        return registers_table  


    # set register name
    def set_reg_name_str(self):
        pass  


    def get_reg_name_str(self, uc_reg):
        adapter = {}
        adapter.update(reg_map)
        adapter = {v: k for k, v in adapter.items()}

        if uc_reg in adapter:
            return adapter[uc_reg]
        # invalid
        return None   


    def get_register(self, register):
        if type(register) == str:
            register = self.get_reg_name(register)  
        return self.ql.uc.reg_read(register)


    def set_register(self, register, value):
        if type(register) == str:
            register = self.get_reg_name(register)  
        return self.ql.uc.reg_write(register, value)


    def get_reg_name(self, uc_reg_name):
        adapter = {}
        adapter.update(reg_map)
        if uc_reg_name in adapter:
            return adapter[uc_reg_name]
        # invalid
        return None
