#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
from unicorn import *
from unicorn.arm64_const import *
from struct import pack
from .arch import Arch

class ARM64(Arch):
    def __init__(self, ql):
        super(ARM64, self).__init__(ql)


    def stack_push(self, value):
        SP = self.ql.uc.reg_read(UC_ARM64_REG_SP)
        SP -= 8
        self.ql.uc.mem_write(SP, self.ql.pack64(value))
        self.ql.uc.reg_write(UC_ARM64_REG_SP, SP)
        return SP


    def stack_pop(self):
        SP = self.ql.uc.reg_read(UC_ARM64_REG_SP)
        data = self.ql.unpack64(self.ql.uc.mem_read(SP, 8))
        self.ql.uc.reg_write(UC_ARM64_REG_SP, SP + 8)
        return data


    def stack_read(self, offset):
        SP = self.ql.uc.reg_read(UC_ARM64_REG_SP)
        return self.ql.unpack64(self.ql.uc.mem_read(SP + offset, 8))


    def stack_write(self, offset, data):
        SP = self.ql.uc.reg_read(UC_ARM64_REG_SP)
        return self.ql.uc.mem_write(SP + offset, self.ql.pack64(data))

    # set PC
    def set_pc(self, value):
        self.ql.uc.reg_write(UC_ARM64_REG_PC, value)


    # get PC
    def get_pc(self):
        return self.ql.uc.reg_read(UC_ARM64_REG_PC)


    # set stack pointer
    def set_sp(self, value):
        self.ql.uc.reg_write(UC_ARM64_REG_PC, value)


    # get stack pointer
    def get_sp(self):
        return self.ql.uc.reg_read(UC_ARM64_REG_PC)


    # get stack pointer register
    def get_reg_sp(self):
        return UC_ARM64_REG_SP


    # get pc register pointer
    def get_reg_pc(self):
        return UC_ARM64_REG_PC

    def get_reg_table(self):
        registers_table = [
            UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
            UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5,
            UC_ARM64_REG_X6, UC_ARM64_REG_X7, UC_ARM64_REG_X8,
            UC_ARM64_REG_X9, UC_ARM64_REG_X10, UC_ARM64_REG_X11,
            UC_ARM64_REG_X12, UC_ARM64_REG_X13, UC_ARM64_REG_X14,
            UC_ARM64_REG_X15, UC_ARM64_REG_X16, UC_ARM64_REG_X17,
            UC_ARM64_REG_X18, UC_ARM64_REG_X19, UC_ARM64_REG_X20,
            UC_ARM64_REG_X21, UC_ARM64_REG_X22, UC_ARM64_REG_X23,
            UC_ARM64_REG_X24, UC_ARM64_REG_X25, UC_ARM64_REG_X26,
            UC_ARM64_REG_X27, UC_ARM64_REG_X28, UC_ARM64_REG_X29,
            UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC
            ]
        return registers_table          