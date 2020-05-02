#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from unicorn import *
from unicorn.mips_const import *

from qiling.const import *
from .arch import QlArch
from .mips32_const import *


class QlArchMIPS32(QlArch):
    def __init__(self, ql):
        super(QlArchMIPS32, self).__init__(ql)


    def stack_push(self, value):
        SP = self.ql.register(UC_MIPS_REG_SP)
        SP -= 4
        self.ql.mem.write(SP, self.ql.pack32(value))
        self.ql.register(UC_MIPS_REG_SP, SP)
        return SP


    def stack_pop(self):
        SP = self.ql.register(UC_MIPS_REG_SP)
        data = self.ql.unpack32(self.ql.mem.read(SP, 4))
        self.ql.register(UC_MIPS_REG_SP, SP + 4)
        return data


    def stack_read(self, offset):
        SP = self.ql.register(UC_MIPS_REG_SP)
        return self.ql.unpack32(self.ql.mem.read(SP + offset, 4))


    def stack_write(self, offset, data):
        SP = self.ql.register(UC_MIPS_REG_SP)
        return self.ql.mem.write(SP + offset, self.ql.pack32(data))

    # get initialized unicorn engine
    def get_init_uc(self):
        if self.ql.archtype== QL_ARCH.MIPS32:
            if self.ql.archendian == QL_ENDIAN.EB:
                uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN)
            else:
                uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)
        return uc

    # set PC
    def set_pc(self, value):
        self.ql.register(UC_MIPS_REG_PC, value)


    # get PC
    def get_pc(self):
        return self.ql.register(UC_MIPS_REG_PC)


    # set stack pointer
    def set_sp(self, value):
        self.ql.register(UC_MIPS_REG_SP, value)


    # get stack pointer
    def get_sp(self):
        return self.ql.register(UC_MIPS_REG_SP)


    # get stack pointer register
    def get_name_sp(self):
        return UC_MIPS_REG_SP


    # get pc register pointer
    def get_name_pc(self):
        return UC_MIPS_REG_PC


    def get_reg_table(self):
        registers_table = []
        adapter = {}
        adapter.update(reg_map)
        registers = {k: v for k, v in adapter.items()}
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


    def get_register(self, register_str):
        if type(register_str) == str:
            register_str = self.get_reg_name(register_str)  
        return self.ql.uc.reg_read(register_str)


    def set_register(self, register_str, value):
        if type(register_str) == str:
            register_str = self.get_reg_name(register_str)  
        return self.ql.uc.reg_write(register_str, value)


    def get_reg_name(self, uc_reg_name):
        adapter = {}
        adapter.update(reg_map)
        if uc_reg_name in adapter:
            return adapter[uc_reg_name]
        # invalid
        return None