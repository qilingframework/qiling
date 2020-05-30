#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from unicorn import *
from unicorn.arm_const import *

from qiling.const import *
from .arch import QlArch
from .sparc_const import *

class QlArchSPARC(QlArch):
    def __init__(self, ql):
        super(QlArchSPARC, self).__init__(ql)
        register_mappings = [
            reg_map
        ]

        for reg_maper in register_mappings:
            self.ql.reg.expand_mapping(reg_maper)

        self.ql.reg.register_sp(reg_map["sp"])
        self.ql.reg.register_pc(reg_map["pc"])

    # get initialized unicorn engine
    def get_init_uc(self):
        if self.ql.archendian == QL_ENDIAN.EB:
            uc = Uc(UC_ARCH_SPARC, UC_MODE_SPARC32|UC_MODE_BIG_ENDIAN)
        else:
            uc = Uc(UC_ARCH_SPARC, UC_MODE_SPARC32)
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


    def get_reg_name(self, uc_reg_name):
        adapter = {}
        adapter.update(reg_map)
        if uc_reg_name in adapter:
            return adapter[uc_reg_name]
        # invalid
        return None


class QlArchSPARC64(QlArch):
	""" TODO : implement 64-bit emulation of SPARC binaries """
	pass