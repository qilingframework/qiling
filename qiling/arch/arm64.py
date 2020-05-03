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


    # set PC
    def set_pc(self, value):
        self.ql.reg.pc = value


    # get PC
    def get_pc(self):
        return self.ql.reg.pc


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


    def enable_vfp(self):
        self.ql.reg.cpacr_el1 = self.ql.reg.cpacr_el1 | 0x300000


    def get_reg_name(self, uc_reg_name):
        adapter = {}
        adapter.update(reg_map)
        if uc_reg_name in adapter:
            return adapter[uc_reg_name]
        # invalid
        return None
