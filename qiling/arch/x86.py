#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
from unicorn import *
from unicorn.x86_const import *

from struct import pack

from .arch import QlArch
from .x86_const import *
from qiling.const import *
from qiling.exception import *

class QlArchX86(QlArch):
    def __init__(self, ql):
        super(QlArchX86, self).__init__(ql)


    def stack_push(self, value):
        SP = self.ql.register(UC_X86_REG_ESP)
        SP -= 4
        self.ql.mem.write(SP, self.ql.pack32(value))
        self.ql.register(UC_X86_REG_ESP, SP)
        return SP

    def stack_pop(self):
        SP = self.ql.register(UC_X86_REG_ESP)
        data = self.ql.unpack32(self.ql.mem.read(SP, 4))
        self.ql.register(UC_X86_REG_ESP, SP + 4)
        return data


    def stack_read(self, offset):
        SP = self.ql.register(UC_X86_REG_ESP)
        return self.ql.unpack32(self.ql.mem.read(SP + offset, 4))


    def stack_write(self, offset, data):
        SP = self.ql.register(UC_X86_REG_ESP)
        return self.ql.mem.write(SP + offset, self.ql.pack32(data))


    # get initialized unicorn engine
    def get_init_uc(self):
        uc = Uc(UC_ARCH_X86, UC_MODE_32)  
        return uc


    # set PC
    def set_pc(self, value):
        self.ql.register(UC_X86_REG_EIP, value)


    # get PC
    def get_pc(self):
        return self.ql.register(UC_X86_REG_EIP)


    # set stack pointer
    def set_sp(self, value):
        self.ql.register(UC_X86_REG_ESP, value)


    # get stack pointer
    def get_sp(self):
        return self.ql.register(UC_X86_REG_ESP)


    # get stack pointer register
    def get_name_sp(self):
        return UC_X86_REG_ESP


    # get pc register pointer
    def get_name_pc(self):
        return UC_X86_REG_EIP


    def get_reg_table(self):
        registers_table = [
            UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX,
            UC_X86_REG_EBX, UC_X86_REG_ESP, UC_X86_REG_EBP,
            UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EIP,
            UC_X86_REG_EFLAGS, UC_X86_REG_CS, UC_X86_REG_SS,
            UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_FS,
            UC_X86_REG_GS, UC_X86_REG_ST0, UC_X86_REG_ST1,
            UC_X86_REG_ST2, UC_X86_REG_ST3, UC_X86_REG_ST4,
            UC_X86_REG_ST5, UC_X86_REG_ST6, UC_X86_REG_ST7
            ]
        return registers_table

    # set register name
    def set_reg_name_str(self):
        pass  

    def get_reg_name_str(self, uc_reg):
        adapter = {
            UC_X86_REG_EAX: "EAX", 
            UC_X86_REG_ECX: "ECX", 
            UC_X86_REG_EDX: "EDX",
            UC_X86_REG_EBX: "EBX", 
            UC_X86_REG_ESP: "ESP", 
            UC_X86_REG_EBP: "EBP",
            UC_X86_REG_ESI: "ESI", 
            UC_X86_REG_EDI: "EDI", 
            UC_X86_REG_EIP: "EIP",
            UC_X86_REG_EFLAGS: "EF", 
            UC_X86_REG_CS: "CS", 
            UC_X86_REG_SS: "SS",
            UC_X86_REG_DS: "DS", 
            UC_X86_REG_ES: "ES", 
            UC_X86_REG_FS: "FS",
            UC_X86_REG_GS: "GS", 
            UC_X86_REG_ST0: "ST0", 
            UC_X86_REG_ST1: "ST1",
            UC_X86_REG_ST2: "ST2", 
            UC_X86_REG_ST3: "ST3", 
            UC_X86_REG_ST4: "ST4",
            UC_X86_REG_ST5: "ST5", 
            UC_X86_REG_ST6: "ST6", 
            UC_X86_REG_ST7: "ST7"
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
            "EAX": UC_X86_REG_EAX, 
            "ECX": UC_X86_REG_ECX, 
            "EDX": UC_X86_REG_EDX,
            "EBX": UC_X86_REG_EBX, 
            "ESP": UC_X86_REG_ESP, 
            "EBP": UC_X86_REG_EBP,
            "ESI": UC_X86_REG_ESI, 
            "EDI": UC_X86_REG_EDI, 
            "EIP": UC_X86_REG_EIP,
            "EF" :UC_X86_REG_EFLAGS, 
            "CS": UC_X86_REG_CS, 
            "SS": UC_X86_REG_SS,
            "DS": UC_X86_REG_DS, 
            "ES": UC_X86_REG_ES, 
            "FS": UC_X86_REG_FS,
            "GS": UC_X86_REG_GS, 
            "ST0": UC_X86_REG_ST0, 
            "ST1": UC_X86_REG_ST1,
            "ST2": UC_X86_REG_ST2, 
            "ST3": UC_X86_REG_ST3, 
            "ST4": UC_X86_REG_ST4,
            "ST5": UC_X86_REG_ST5, 
            "ST6": UC_X86_REG_ST6, 
            "ST7": UC_X86_REG_ST7
        }
        if uc_reg_name in adapter:
            return adapter[uc_reg_name]
        # invalid
        return None

class QlArchX8664(QlArch):
    def __init__(self, ql):
        super(QlArchX8664, self).__init__(ql)


    def stack_push(self, value):
        SP = self.ql.register(UC_X86_REG_RSP)
        SP -= 8
        self.ql.mem.write(SP, self.ql.pack64(value))
        self.ql.register(UC_X86_REG_RSP, SP)
        return SP

    def stack_pop(self):
        SP = self.ql.register(UC_X86_REG_RSP)
        data = self.ql.unpack64(self.ql.mem.read(SP, 8))
        self.ql.register(UC_X86_REG_RSP, SP + 8)
        return data


    def stack_read(self, offset):
        SP = self.ql.register(UC_X86_REG_RSP)
        return self.ql.unpack64(self.ql.mem.read(SP + offset, 8))


    def stack_write(self, offset, data):
        SP = self.ql.register(UC_X86_REG_RSP)
        return self.ql.mem.write(SP + offset, self.ql.pack64(data))


    # get initialized unicorn engine
    def get_init_uc(self):
        uc = Uc(UC_ARCH_X86, UC_MODE_64)  
        return uc


    # set PC
    def set_pc(self, value):
        self.ql.register(UC_X86_REG_RIP, value)


    # get PC
    def get_pc(self):
        return self.ql.register(UC_X86_REG_RIP)


    # set stack pointer
    def set_sp(self, value):
        self.ql.register(UC_X86_REG_RSP, value)


    # get stack pointer
    def get_sp(self):
        return self.ql.register(UC_X86_REG_RSP)


    # get stack pointer register
    def get_name_sp(self):
        return UC_X86_REG_RSP


    # get pc register pointer
    def get_name_pc(self):
        return UC_X86_REG_RIP


    def get_reg_table(self):
        registers_table = [
            UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX,
            UC_X86_REG_RDX, UC_X86_REG_RSI, UC_X86_REG_RDI,
            UC_X86_REG_RBP, UC_X86_REG_RSP, UC_X86_REG_R8,
            UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
            UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14,
            UC_X86_REG_R15, UC_X86_REG_RIP, UC_X86_REG_EFLAGS,
            UC_X86_REG_CS, UC_X86_REG_SS, UC_X86_REG_DS,
            UC_X86_REG_ES, UC_X86_REG_FS, UC_X86_REG_GS,
            UC_X86_REG_ST0, UC_X86_REG_ST1,
            UC_X86_REG_ST2, UC_X86_REG_ST3, UC_X86_REG_ST4,
            UC_X86_REG_ST5, UC_X86_REG_ST6, UC_X86_REG_ST7
            ]
        return registers_table  

    # set register name
    def set_reg_name_str(self):
        pass  

    def get_reg_name_str(self, uc_reg):
        adapter = {
            UC_X86_REG_RAX: "RAX", 
            UC_X86_REG_RCX: "RCX", 
            UC_X86_REG_RDX: "RDX",
            UC_X86_REG_RBX: "RBX", 
            UC_X86_REG_RSP: "RSP", 
            UC_X86_REG_RBP: "RBP",
            UC_X86_REG_RSI: "RSI", 
            UC_X86_REG_RDI: "RDI", 
            UC_X86_REG_RIP: "RIP",
            UC_X86_REG_R8: "R8",
            UC_X86_REG_R9: "R9", 
            UC_X86_REG_R10: "R10",
            UC_X86_REG_R11: "R11",
            UC_X86_REG_R12: "R12", 
            UC_X86_REG_R13: "R13", 
            UC_X86_REG_R14: "R14",
            UC_X86_REG_R15: "R15",
            UC_X86_REG_EFLAGS: "EF", 
            UC_X86_REG_CS: "CS", 
            UC_X86_REG_SS: "SS",
            UC_X86_REG_DS: "DS", 
            UC_X86_REG_ES: "ES", 
            UC_X86_REG_FS: "FS",
            UC_X86_REG_GS: "GS", 
            UC_X86_REG_ST0: "ST0", 
            UC_X86_REG_ST1: "ST1",
            UC_X86_REG_ST2: "ST2", 
            UC_X86_REG_ST3: "ST3", 
            UC_X86_REG_ST4: "ST4",
            UC_X86_REG_ST5: "ST5", 
            UC_X86_REG_ST6: "ST6", 
            UC_X86_REG_ST7: "ST7"
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
            "RAX": UC_X86_REG_RAX, 
            "RCX": UC_X86_REG_RCX, 
            "RDX": UC_X86_REG_RDX,
            "RBX": UC_X86_REG_RBX, 
            "RSP": UC_X86_REG_RSP, 
            "RBP": UC_X86_REG_RBP,
            "RSI": UC_X86_REG_RSI, 
            "RDI": UC_X86_REG_RDI, 
            "RIP": UC_X86_REG_RIP,
            "R8": UC_X86_REG_R8,
            "R9": UC_X86_REG_R9, 
            "R10": UC_X86_REG_R10,
            "R11": UC_X86_REG_R11,
            "R12": UC_X86_REG_R12, 
            "R13": UC_X86_REG_R13, 
            "R14": UC_X86_REG_R14,
            "R15": UC_X86_REG_R15,
            "EF" :UC_X86_REG_EFLAGS, 
            "CS": UC_X86_REG_CS, 
            "SS": UC_X86_REG_SS,
            "DS": UC_X86_REG_DS, 
            "ES": UC_X86_REG_ES, 
            "FS": UC_X86_REG_FS,
            "GS": UC_X86_REG_GS, 
            "ST0": UC_X86_REG_ST0, 
            "ST1": UC_X86_REG_ST1,
            "ST2": UC_X86_REG_ST2, 
            "ST3": UC_X86_REG_ST3, 
            "ST4": UC_X86_REG_ST4,
            "ST5": UC_X86_REG_ST5, 
            "ST6": UC_X86_REG_ST6, 
            "ST7": UC_X86_REG_ST7
        }
        if uc_reg_name in adapter:
            return adapter[uc_reg_name]
        # invalid
        return None                       

class GDTManager:
    # Added GDT management module.
    def __init__(self, ql, GDT_ADDR = QL_X86_GDT_ADDR, GDT_LIMIT =  QL_X86_GDT_LIMIT, GDT_ENTRY_ENTRIES = 16):
        if ql.mem.is_mapped(GDT_ADDR, GDT_LIMIT) == False:
            ql.mem.map(GDT_ADDR, GDT_LIMIT, info="[GDT]")
        else:
            raise QlGDTError("[!] Ql GDT mem map error!")
        # setup GDT by writing to GDTR
        ql.register(UC_X86_REG_GDTR, (0, GDT_ADDR, GDT_LIMIT, 0x0))

        self.ql = ql
        self.gdt_number = GDT_ENTRY_ENTRIES
        # self.gdt_used = [False] * GDT_ENTRY_ENTRIES
        self.gdt_addr = GDT_ADDR
        self.gdt_limit = GDT_LIMIT


    def register_gdt_segment(self, index, SEGMENT_ADDR, SEGMENT_SIZE, SPORT, RPORT):
        # FIXME: Temp fix for FS and GS
        if index in (14,15):
            if self.ql.mem.is_mapped(SEGMENT_ADDR, SEGMENT_ADDR) == False:
                self.ql.mem.map(SEGMENT_ADDR, SEGMENT_ADDR, info="[FS/GS]")

        if index < 0 or index >= self.gdt_number:
            raise QlGDTError("[!] Ql GDT register index error!")
        # create GDT entry, then write GDT entry into GDT table
        gdt_entry = self._create_gdt_entry(SEGMENT_ADDR, SEGMENT_SIZE, SPORT, QL_X86_F_PROT_32)
        self.ql.mem.write(self.gdt_addr + (index << 3), gdt_entry)
        # self.gdt_used[index] = True

    def get_gdt_buf(self, start, end):
        return self.ql.mem.read(self.gdt_addr + (start << 3), (end << 3) - (start << 3))

    def set_gdt_buf(self, start, end, buf):
        return self.ql.mem.write(self.gdt_addr + (start << 3), buf[ : (end << 3) - (start << 3)])

    def get_free_idx(self, start = 0, end = -1):
        # The Linux kernel determines whether the segment is empty by judging whether the content in the current GDT segment is 0.
        if end == -1:
            end = self.gdt_number

        idx = -1
        for i in range(start, end):
            if self.ql.unpack64(self.ql.mem.read(self.gdt_addr + (i << 3), 8)) == 0:
                idx = i
                break

        return idx

    def _create_gdt_entry(self, base, limit, access, flags):
        to_ret = limit & 0xffff
        to_ret |= (base & 0xffffff) << 16
        to_ret |= (access & 0xff) << 40
        to_ret |= ((limit >> 16) & 0xf) << 48
        to_ret |= (flags & 0xff) << 52
        to_ret |= ((base >> 24) & 0xff) << 56
        return pack('<Q', to_ret)

    def _create_selector(self, idx, flags):
        to_ret = flags
        to_ret |= idx << 3
        return to_ret

    def create_selector(self, idx, flags):
        return self._create_selector(idx, flags)

def ql_x86_register_cs(self):
    # While debugging the linux kernel segment, the cs segment was found on the third segment of gdt.
    self.gdtm.register_gdt_segment(3, 0, 0xfffff000, QL_X86_A_PRESENT | QL_X86_A_CODE | QL_X86_A_CODE_READABLE | QL_X86_A_PRIV_3 | QL_X86_A_EXEC | QL_X86_A_DIR_CON_BIT, QL_X86_S_GDT | QL_X86_S_PRIV_3)
    self.ql.register(UC_X86_REG_CS, self.gdtm.create_selector(3, QL_X86_S_GDT | QL_X86_S_PRIV_3))

def ql_x8664_register_cs(self):
    # While debugging the linux kernel segment, the cs segment was found on the sixth segment of gdt.
    self.gdtm.register_gdt_segment(6, 0, 0xfffffffffffff000, QL_X86_A_PRESENT | QL_X86_A_CODE | QL_X86_A_CODE_READABLE | QL_X86_A_PRIV_3 | QL_X86_A_EXEC | QL_X86_A_DIR_CON_BIT, QL_X86_S_GDT | QL_X86_S_PRIV_3)
    self.ql.register(UC_X86_REG_CS, self.gdtm.create_selector(6, QL_X86_S_GDT | QL_X86_S_PRIV_3))

def ql_x86_register_ds_ss_es(self):
    # TODO : The section permission here should be QL_X86_A_PRIV_3, but I do n’t know why it can only be set to QL_X86_A_PRIV_0.
    # While debugging the Linux kernel segment, I found that the three segments DS, SS, and ES all point to the same location in the GDT table. 
    # This position is the fifth segment table of GDT.
    self.gdtm.register_gdt_segment(5, 0, 0xfffff000, QL_X86_A_PRESENT | QL_X86_A_DATA | QL_X86_A_DATA_WRITABLE | QL_X86_A_PRIV_0 | QL_X86_A_DIR_CON_BIT, QL_X86_S_GDT | QL_X86_S_PRIV_0)
    self.ql.register(UC_X86_REG_DS, self.gdtm.create_selector(5, QL_X86_S_GDT | QL_X86_S_PRIV_0))
    self.ql.register(UC_X86_REG_SS, self.gdtm.create_selector(5, QL_X86_S_GDT | QL_X86_S_PRIV_0))
    self.ql.register(UC_X86_REG_ES, self.gdtm.create_selector(5, QL_X86_S_GDT | QL_X86_S_PRIV_0))

def ql_x8664_register_ds_ss_es(self):
    # TODO : The section permission here should be QL_X86_A_PRIV_3, but I do n’t know why it can only be set to QL_X86_A_PRIV_0.
    # When I debug the Linux kernel, I find that only the SS is set to the fifth segment table, and the rest are not set.
    self.gdtm.register_gdt_segment(5, 0, 0xfffff000, QL_X86_A_PRESENT | QL_X86_A_DATA | QL_X86_A_DATA_WRITABLE | QL_X86_A_PRIV_0 | QL_X86_A_DIR_CON_BIT, QL_X86_S_GDT | QL_X86_S_PRIV_0)
    # ql.register(UC_X86_REG_DS, ql.os.gdtm.create_selector(5, QL_X86_S_GDT | QL_X86_S_PRIV_0))
    self.ql.register(UC_X86_REG_SS, self.gdtm.create_selector(5, QL_X86_S_GDT | QL_X86_S_PRIV_0))
    # ql.register(UC_X86_REG_ES, ql.os.gdtm.create_selector(5, QL_X86_S_GDT | QL_X86_S_PRIV_0))

def ql_x86_register_gs(self):
    self.gdtm.register_gdt_segment(15, GS_SEGMENT_ADDR, GS_SEGMENT_SIZE, QL_X86_A_PRESENT | QL_X86_A_DATA | QL_X86_A_DATA_WRITABLE | QL_X86_A_PRIV_3 | QL_X86_A_DIR_CON_BIT, QL_X86_S_GDT |  QL_X86_S_PRIV_3)
    self.ql.register(UC_X86_REG_GS, self.gdtm.create_selector(15, QL_X86_S_GDT | QL_X86_S_PRIV_0))

def ql_x86_register_fs(self):
    self.gdtm.register_gdt_segment(14, FS_SEGMENT_ADDR, FS_SEGMENT_SIZE, QL_X86_A_PRESENT | QL_X86_A_DATA | QL_X86_A_DATA_WRITABLE | QL_X86_A_PRIV_3 | QL_X86_A_DIR_CON_BIT, QL_X86_S_GDT |  QL_X86_S_PRIV_3)
    self.ql.register(UC_X86_REG_FS, self.gdtm.create_selector(14,  QL_X86_S_GDT |  QL_X86_S_PRIV_3))


def ql_x8664_set_gs(ql):
    if ql.mem.is_mapped(GS_SEGMENT_ADDR, GS_SEGMENT_SIZE) == False:
        ql.mem.map(GS_SEGMENT_ADDR, GS_SEGMENT_SIZE, info="[GS]")
    ql.reg.msr(GSMSR, GS_SEGMENT_ADDR)


def ql_x8664_get_gs(ql):
    return ql.reg.msr(GSMSR)


def ql_x8664_set_fs(ql, addr):
    ql.reg.msr(FSMSR, addr)


def ql_x8664_get_fs(ql):
    return ql.reg.msr(FSMSR)
