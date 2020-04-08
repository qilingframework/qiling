#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
from unicorn import *
from unicorn.arm_const import *
from struct import pack
from .arch import QlArch

from qiling.const import *
from unicorn import *
from unicorn.arm_const import *

# def ql_arm_check_thumb(uc, reg_cpsr):
#     mode = UC_MODE_ARM
#     if reg_cpsr & 0b100000 != 0:
#         mode = UC_MODE_THUMB
#         return mode

class QlArchARM(QlArch):
    def __init__(self, ql):
        super(QlArchARM, self).__init__(ql)


    def stack_push(self, value):
        SP = self.ql.register(UC_ARM_REG_SP)
        SP -= 4
        self.ql.mem.write(SP, self.ql.pack32(value))
        self.ql.register(UC_ARM_REG_SP, SP)
        return SP


    def stack_pop(self):
        SP = self.ql.register(UC_ARM_REG_SP)
        data = self.ql.unpack32(self.ql.mem.read(SP, 4))
        self.ql.register(UC_ARM_REG_SP, SP + 4)
        return data


    def stack_read(self, offset):
        SP = self.ql.register(UC_ARM_REG_SP)
        return self.ql.unpack32(self.ql.mem.read(SP + offset, 4))


    def stack_write(self, offset, data):
        SP = self.ql.register(UC_ARM_REG_SP)
        return self.ql.mem.write(SP + offset, self.ql.pack32(data))


    # get initialized unicorn engine
    def get_init_uc(self):
        if self.ql.archendian == QL_ENDIAN_EB:
            uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
            # FIXME: unicorn engine not able to choose ARM or Thumb automatically
            #uc = Uc(UC_ARCH_ARM, UC_MODE_ARM + UC_MODE_BIG_ENDIAN)
        else:
            uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)    
        return uc

    # set PC
    def set_pc(self, value):
        self.ql.register(UC_ARM_REG_PC, value)


    # get PC
    def get_pc(self):
        mode = self.ql.arch.check_thumb()
        if mode == UC_MODE_THUMB:
            append = 1
        else:
            append = 0
        return self.ql.register(UC_ARM_REG_PC) + append


    # set stack pointer
    def set_sp(self, value):
        self.ql.register(UC_ARM_REG_SP, value)


    # get stack pointer
    def get_sp(self):
        return self.ql.register(UC_ARM_REG_SP)


    # get stack pointer register
    def get_reg_sp(self):
        return UC_ARM_REG_SP


    # get pc register pointer
    def get_reg_pc(self):
        return UC_ARM_REG_PC

    def enable_vfp(self):
        tmp_val = self.ql.register(UC_ARM_REG_C1_C0_2)
        tmp_val = tmp_val | (0xf << 20)
        self.ql.register(UC_ARM_REG_C1_C0_2, tmp_val)
        if self.ql.archendian == QL_ENDIAN_EB:
            enable_vfp = 0x40000000
            #enable_vfp = 0x00000040
        else:
            enable_vfp = 0x40000000
        self.ql.register(UC_ARM_REG_FPEXC, enable_vfp)
        self.ql.dprint(0, "[+] Enable ARM VFP")


    def check_thumb(self):
    
        reg_cpsr = self.ql.register(UC_ARM_REG_CPSR)
        if self.ql.archendian == QL_ENDIAN_EB:
            reg_cpsr_v = 0b100000
            # reg_cpsr_v = 0b000000
        else:
            reg_cpsr_v = 0b100000

        mode = UC_MODE_ARM
        if (reg_cpsr & reg_cpsr_v) != 0:
            mode = UC_MODE_THUMB
            self.ql.dprint(0, "[+] Enable ARM THUMB")
        return mode

    def get_reg_table(self):
        registers_table = [
            UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
            UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5,
            UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8,
            UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
            UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR,
            UC_ARM_REG_PC, UC_ARM_REG_CPSR
            ]
        return registers_table

    # set register name
    def set_reg_name_str(self):
        pass  

    def get_reg_name_str(self, uc_reg):
        adapter = {
            UC_ARM_REG_R0: "R0",
            UC_ARM_REG_R1: "R1", 
            UC_ARM_REG_R2: "R2",
            UC_ARM_REG_R3: "R3", 
            UC_ARM_REG_R4: "R4", 
            UC_ARM_REG_R5: "R5",
            UC_ARM_REG_R6: "R6", 
            UC_ARM_REG_R7: "R7", 
            UC_ARM_REG_R8: "R8",
            UC_ARM_REG_R9: "R9", 
            UC_ARM_REG_R10: "R10", 
            UC_ARM_REG_R11: "R11",
            UC_ARM_REG_R12: "R12", 
            UC_ARM_REG_SP: "SP", 
            UC_ARM_REG_LR: "LR",
            UC_ARM_REG_PC: "PC", 
            UC_ARM_REG_CPSR: "CPSR",
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


    def get_reg_name(self, uc_reg_name):
        adapter = {
            "R0": UC_ARM_REG_R0,
            "R1": UC_ARM_REG_R1, 
            "R2": UC_ARM_REG_R2,
            "R3": UC_ARM_REG_R3, 
            "R4": UC_ARM_REG_R4,
            "R5": UC_ARM_REG_R5,
            "R6": UC_ARM_REG_R6, 
            "R7": UC_ARM_REG_R7, 
            "R8": UC_ARM_REG_R8,
            "R9": UC_ARM_REG_R9, 
            "R10": UC_ARM_REG_R10, 
            "R11": UC_ARM_REG_R11,
            "R12": UC_ARM_REG_R12, 
            "SP": UC_ARM_REG_SP, 
            "LR": UC_ARM_REG_LR,
            "PC": UC_ARM_REG_PC, 
            "CPSR": UC_ARM_REG_CPSR,
        }
        if uc_reg_name in adapter:
            return adapter[uc_reg_name]
        # invalid
        return None