#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
from unicorn import *
from unicorn.arm64_const import *
from struct import pack
from .arch import Arch
from qiling.const import *

class ARM64(Arch):
    def __init__(self, ql):
        super(ARM64, self).__init__(ql)


    def stack_push(self, value):
        SP = self.ql.register(UC_ARM64_REG_SP)
        SP -= 8
        self.ql.mem.write(SP, self.ql.pack64(value))
        self.ql.register(UC_ARM64_REG_SP, SP)
        return SP


    def stack_pop(self):
        SP = self.ql.register(UC_ARM64_REG_SP)
        data = self.ql.unpack64(self.ql.mem.read(SP, 8))
        self.ql.register(UC_ARM64_REG_SP, SP + 8)
        return data


    def stack_read(self, offset):
        SP = self.ql.register(UC_ARM64_REG_SP)
        return self.ql.unpack64(self.ql.mem.read(SP + offset, 8))


    def stack_write(self, offset, data):
        SP = self.ql.register(UC_ARM64_REG_SP)
        return self.ql.mem.write(SP + offset, self.ql.pack64(data))


    # set PC
    def set_pc(self, value):
        self.ql.register(UC_ARM64_REG_PC, value)

    # get PC
    def get_pc(self):
        return self.ql.register(UC_ARM64_REG_PC)


    # set stack pointer
    def set_sp(self, value):
        self.ql.register(UC_ARM64_REG_SP, value)


    # get stack pointer
    def get_sp(self):
        return self.ql.register(UC_ARM64_REG_SP)


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

    # set register name
    def set_reg_name_str(self):
        pass  
    
    def get_reg_name_str(self, uc_reg):
        adapter = {
            UC_ARM64_REG_X0: "X0", 
            UC_ARM64_REG_X1: "X1", 
            UC_ARM64_REG_X2: "X2",
            UC_ARM64_REG_X3: "X3", 
            UC_ARM64_REG_X4: "X4", 
            UC_ARM64_REG_X5: "X5",
            UC_ARM64_REG_X6: "X6", 
            UC_ARM64_REG_X7: "X7", 
            UC_ARM64_REG_X8: "X8",
            UC_ARM64_REG_X9: "X9", 
            UC_ARM64_REG_X10: "X10", 
            UC_ARM64_REG_X11: "X11",
            UC_ARM64_REG_X12: "X12", 
            UC_ARM64_REG_X13: "X13", 
            UC_ARM64_REG_X14: "X14",
            UC_ARM64_REG_X15: "X15", 
            UC_ARM64_REG_X16: "X16", 
            UC_ARM64_REG_X17: "X17",
            UC_ARM64_REG_X18: "X18", 
            UC_ARM64_REG_X19: "X19", 
            UC_ARM64_REG_X20: "X20",
            UC_ARM64_REG_X21: "X21", 
            UC_ARM64_REG_X22: "X22", 
            UC_ARM64_REG_X23: "X23",
            UC_ARM64_REG_X24: "X24", 
            UC_ARM64_REG_X25: "X25", 
            UC_ARM64_REG_X26: "X26",
            UC_ARM64_REG_X27: "X27", 
            UC_ARM64_REG_X28: "X28", 
            UC_ARM64_REG_X29: "X29",
            UC_ARM64_REG_X30: "X30", 
            UC_ARM64_REG_SP: "SP", 
            UC_ARM64_REG_PC: "PC"
        }
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

    def enable_vfp(self):
        ARM64FP = self.ql.register(UC_ARM64_REG_CPACR_EL1)
        ARM64FP |= 0x300000
        self.ql.register(UC_ARM64_REG_CPACR_EL1, ARM64FP)

    def get_reg_name(self, uc_reg_name):
        adapter = {
            "X0": UC_ARM64_REG_X0, 
            "X1": UC_ARM64_REG_X1, 
            "X2": UC_ARM64_REG_X2,
            "X3": UC_ARM64_REG_X3, 
            "X4": UC_ARM64_REG_X4, 
            "X5": UC_ARM64_REG_X5,
            "X6": UC_ARM64_REG_X6, 
            "X7": UC_ARM64_REG_X7, 
            "X8": UC_ARM64_REG_X8,
            "X9": UC_ARM64_REG_X9, 
            "X10": UC_ARM64_REG_X10, 
            "X11": UC_ARM64_REG_X11,
            "X12": UC_ARM64_REG_X12, 
            "X13": UC_ARM64_REG_X13, 
            "X14": UC_ARM64_REG_X14,
            "X15": UC_ARM64_REG_X15, 
            "X16": UC_ARM64_REG_X16, 
            "X17": UC_ARM64_REG_X17,
            "X18": UC_ARM64_REG_X18, 
            "X19": UC_ARM64_REG_X19, 
            "X20": UC_ARM64_REG_X20,
            "X21": UC_ARM64_REG_X21, 
            "X22": UC_ARM64_REG_X22, 
            "X23": UC_ARM64_REG_X23,
            "X24": UC_ARM64_REG_X24, 
            "X25": UC_ARM64_REG_X25, 
            "X26": UC_ARM64_REG_X26,
            "X27": UC_ARM64_REG_X27, 
            "X28": UC_ARM64_REG_X28, 
            "X29": UC_ARM64_REG_X29,
            "X30": UC_ARM64_REG_X30, 
            "SP": UC_ARM64_REG_SP, 
            "PC": UC_ARM64_REG_PC,
        }
        if uc_reg_name in adapter:
            return adapter[uc_reg_name]
        # invalid
        return None