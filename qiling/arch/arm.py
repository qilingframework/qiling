#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
from unicorn import *
from unicorn.arm_const import *
from struct import pack
from .arch import Arch

def ql_arm_check_thumb(uc, reg_cpsr):
    mode = UC_MODE_ARM
    if reg_cpsr & 0b100000 != 0:
        mode = UC_MODE_THUMB
        return mode

class ARM(Arch):
    def __init__(self, ql):
        super(ARM, self).__init__(ql)


    def stack_push(self, value):
        SP = self.ql.uc.reg_read(UC_ARM_REG_SP)
        SP -= 4
        self.ql.uc.mem_write(SP, self.ql.pack32(value))
        self.ql.uc.reg_write(UC_ARM_REG_SP, SP)
        return SP


    def stack_pop(self):
        SP = self.ql.uc.reg_read(UC_ARM_REG_SP)
        data = self.ql.unpack32(self.ql.uc.mem_read(SP, 4))
        self.ql.uc.reg_write(UC_ARM_REG_SP, SP + 4)
        return data


    def stack_read(self, offset):
        SP = self.ql.uc.reg_read(UC_ARM_REG_SP)
        return self.ql.unpack32(self.ql.uc.mem_read(SP + offset, 4))


    def stack_write(self, offset, data):
        SP = self.ql.uc.reg_read(UC_ARM_REG_SP)
        return self.ql.uc.mem_write(SP + offset, self.ql.pack32(data))


    # set PC
    def set_pc(self, value):
        self.ql.uc.reg_write(UC_ARM_REG_PC, value)


    # get PC
    def get_pc(self):
        reg_cpsr = self.ql.uc.reg_read(UC_ARM_REG_CPSR)
        mode = ql_arm_check_thumb(self.ql.uc, reg_cpsr)
        if mode == UC_MODE_THUMB:
            append = 1
        else:
            append = 0
        return self.ql.uc.reg_read(UC_ARM_REG_PC) + append


    # set stack pointer
    def set_sp(self, value):
        self.ql.uc.reg_write(UC_ARM_REG_SP, value)


    # get stack pointer
    def get_sp(self):
        return self.ql.uc.reg_read(UC_ARM_REG_SP)


    # get stack pointer register
    def get_reg_sp(self):
        return UC_ARM_REG_SP


    # get pc register pointer
    def get_reg_pc(self):
        return UC_ARM_REG_PC