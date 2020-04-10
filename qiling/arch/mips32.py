#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
from unicorn import *
from unicorn.mips_const import *
from struct import pack
from .arch import QlArch

from qiling.const import *
from unicorn import *
from unicorn.arm_const import *

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
        if self.ql.archtype== QL_MIPS32:
            if self.ql.archendian == QL_ENDIAN_EB:
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
    def get_reg_sp(self):
        return UC_MIPS_REG_SP


    # get pc register pointer
    def get_reg_pc(self):
        return UC_MIPS_REG_PC


    def get_reg_table(self):
        registers_table = [
            UC_MIPS_REG_0, UC_MIPS_REG_1, UC_MIPS_REG_2,
            UC_MIPS_REG_3, UC_MIPS_REG_4, UC_MIPS_REG_5,
            UC_MIPS_REG_6, UC_MIPS_REG_7, UC_MIPS_REG_8,
            UC_MIPS_REG_9, UC_MIPS_REG_10, UC_MIPS_REG_11,
            UC_MIPS_REG_12, UC_MIPS_REG_13, UC_MIPS_REG_14,
            UC_MIPS_REG_15, UC_MIPS_REG_16, UC_MIPS_REG_17,
            UC_MIPS_REG_18, UC_MIPS_REG_19, UC_MIPS_REG_20,
            UC_MIPS_REG_21, UC_MIPS_REG_22, UC_MIPS_REG_23,
            UC_MIPS_REG_24, UC_MIPS_REG_25, UC_MIPS_REG_26,
            UC_MIPS_REG_27, UC_MIPS_REG_28, UC_MIPS_REG_29,
            UC_MIPS_REG_30, UC_MIPS_REG_31, UC_MIPS_REG_INVALID,
            UC_MIPS_REG_LO, UC_MIPS_REG_HI, UC_MIPS_REG_INVALID,
            UC_MIPS_REG_INVALID, UC_MIPS_REG_PC
            ]
        return registers_table  

    # set register name
    def set_reg_name_str(self):
        pass  

    def get_reg_name_str(self, uc_reg):
        adapter = {
            UC_MIPS_REG_0: "Z0", # permanently 0
            UC_MIPS_REG_1: "AT",   # assebmler temporary (reserved)
            UC_MIPS_REG_2: "V0",   # value returned by a subroutine
            UC_MIPS_REG_3: "V1", 
            UC_MIPS_REG_4: "A0",   # arguments to a subroutine
            UC_MIPS_REG_5: "A1",
            UC_MIPS_REG_6: "A2", 
            UC_MIPS_REG_7: "A3", 
            UC_MIPS_REG_8: "T0",   # temporary (not preserved across a function call)
            UC_MIPS_REG_9: "T1", 
            UC_MIPS_REG_10: "T2", 
            UC_MIPS_REG_11: "T3",
            UC_MIPS_REG_12: "T4", 
            UC_MIPS_REG_13: "T5", 
            UC_MIPS_REG_14: "T6",
            UC_MIPS_REG_15: "T7", 
            UC_MIPS_REG_16: "S0",  # saved registers (preserved across a function call)
            UC_MIPS_REG_17: "S1",
            UC_MIPS_REG_18: "S2", 
            UC_MIPS_REG_19: "S3", 
            UC_MIPS_REG_20: "S4",
            UC_MIPS_REG_21: "S5", 
            UC_MIPS_REG_22: "S6", 
            UC_MIPS_REG_23: "S7",
            UC_MIPS_REG_24: "T8",   # temporary
            UC_MIPS_REG_25: "T9", 
            UC_MIPS_REG_26: "K0",   # kernel (reserved for OS)
            UC_MIPS_REG_27: "K1", 
            UC_MIPS_REG_28: "GP",   # global pointer
            UC_MIPS_REG_29: "SP",   # stack pointer
            UC_MIPS_REG_30: "FP",   # frame pointer
            UC_MIPS_REG_31: "RA",   # return address
            UC_MIPS_REG_INVALID: "INV",
            UC_MIPS_REG_LO: "LO", 
            UC_MIPS_REG_HI: "HI", 
            UC_MIPS_REG_INVALID: "INV",
            UC_MIPS_REG_INVALID: "INV", 
            UC_MIPS_REG_PC: "PC"
        }
        # return None if uc_reg is invalid
        return adapter.get(uc_reg, None)


    def get_register(self, register_str):
        if type(register_str) == str:
            register_str = self.get_reg_name(register_str)  
        return self.ql.uc.reg_read(register_str)


    def set_register(self, register_str, value):
        if type(register_str) == str:
            register_str = self.get_reg_name(register_str)  
        return self.ql.uc.reg_write(register_str, value)


    def get_reg_name(self, uc_reg_name):
        adapter = {
            "0": UC_MIPS_REG_0, 
            "1": UC_MIPS_REG_1, 
            "2": UC_MIPS_REG_2,
            "3": UC_MIPS_REG_3, 
            "4": UC_MIPS_REG_4, 
            "5": UC_MIPS_REG_5,
            "6": UC_MIPS_REG_6, 
            "7": UC_MIPS_REG_7, 
            "8": UC_MIPS_REG_8,
            "9": UC_MIPS_REG_9, 
            "10": UC_MIPS_REG_10, 
            "11": UC_MIPS_REG_11,
            "12": UC_MIPS_REG_12, 
            "13": UC_MIPS_REG_13, 
            "14": UC_MIPS_REG_14,
            "15": UC_MIPS_REG_15, 
            "16": UC_MIPS_REG_16,
            "17": UC_MIPS_REG_17,
            "18": UC_MIPS_REG_18, 
            "19": UC_MIPS_REG_19, 
            "20": UC_MIPS_REG_20,
            "21": UC_MIPS_REG_21, 
            "22": UC_MIPS_REG_22, 
            "23": UC_MIPS_REG_23,
            "24": UC_MIPS_REG_24, 
            "25": UC_MIPS_REG_25, 
            "26": UC_MIPS_REG_26,
            "27": UC_MIPS_REG_27, 
            "28": UC_MIPS_REG_28, 
            "SP": UC_MIPS_REG_29,
            "30": UC_MIPS_REG_30, 
            "31": UC_MIPS_REG_31, 
            "INV": UC_MIPS_REG_INVALID,
            "LO": UC_MIPS_REG_LO, 
            "HI": UC_MIPS_REG_HI, 
            "INV": UC_MIPS_REG_INVALID,
            "INV":UC_MIPS_REG_INVALID,
            "PC": UC_MIPS_REG_PC,
        }
        # return None if uc_reg_name is invalid
        return adapter.get(uc_reg_name, None)
