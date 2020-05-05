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

        x86_register_mappings = [
            reg_map_8, reg_map_16, reg_map_32,
            reg_map_cr, reg_map_st, reg_map_misc
        ]

        for reg_maper in x86_register_mappings:
            self.ql.reg.expand_mapping(reg_maper)

        self.ql.reg.register_sp(reg_map_32["esp"])
        self.ql.reg.register_pc(reg_map_32["eip"])


    def stack_push(self, value):
        self.ql.reg.esp -= 4
        self.ql.mem.write(self.ql.reg.esp , self.ql.pack32(value))
        return self.ql.reg.esp


    def stack_pop(self):
        data = self.ql.unpack32(self.ql.mem.read(self.ql.reg.esp, 4))
        self.ql.reg.esp += 4
        return data


    def stack_read(self, offset):
        return self.ql.unpack32(self.ql.mem.read(self.ql.reg.esp+offset, 4))


    def stack_write(self, offset, data):
        return self.ql.mem.write(self.ql.reg.esp + offset, self.ql.pack32(data))


    # get register big, mostly use for x86    
    def get_reg_bit(self, register):
        if type(register) == str:
            register = self.get_reg_name(register)
        if register in ({v for k, v in reg_map_32.items()}):
            return 32 


    # get initialized unicorn engine
    def get_init_uc(self):
        uc = Uc(UC_ARCH_X86, UC_MODE_32)  
        return uc


    # set PC
    def set_pc(self, value):
        self.ql.reg.eip = value


    # get PC
    def get_pc(self):
        return self.ql.reg.eip


    # set stack pointer
    def set_sp(self, value):
        self.ql.reg.esp = value


    # get stack pointer
    def get_sp(self):
        return self.ql.reg.esp


    # get stack pointer register
    def get_name_sp(self):
        return reg_map_32["esp"]


    # get pc register pointer
    def get_name_pc(self):
        return reg_map_32["eip"]


    def get_reg_table(self): 
        registers_table = []
        adapter = {}
        adapter.update(reg_map_32)
        adapter.update(reg_map_misc)
        adapter.update(reg_map_st)
        registers = {k:v for k, v in adapter.items()}

        for reg in registers:
            registers_table += [reg]
     
        return registers_table


    # set register name
    def set_reg_name_str(self):
        pass  


    def get_reg_name_str(self, uc_reg): 
        adapter = {}
        adapter.update(reg_map_32)
        adapter.update(reg_map_misc)
        adapter.update(reg_map_st)
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
        adapter.update(reg_map_32)
        adapter.update(reg_map_misc)
        adapter.update(reg_map_st)

        if uc_reg_name in adapter:
            return adapter[uc_reg_name]
        # invalid
        return None


class QlArchX8664(QlArch):
    def __init__(self, ql):
        super(QlArchX8664, self).__init__(ql)

        x64_register_mappings = [
            reg_map_8, reg_map_16, reg_map_32, reg_map_64,
            reg_map_cr, reg_map_st, reg_map_misc
        ]

        for reg_maper in x64_register_mappings:
            self.ql.reg.expand_mapping(reg_maper)

        self.ql.reg.register_sp(reg_map_64["rsp"])
        self.ql.reg.register_pc(reg_map_64["rip"])


    def stack_push(self, value):
        self.ql.reg.rsp -= 8
        self.ql.mem.write(self.ql.reg.rsp, self.ql.pack64(value))
        return self.ql.reg.rsp


    def stack_pop(self):
        data = self.ql.unpack64(self.ql.mem.read(self.ql.reg.rsp, 8))
        self.ql.reg.rsp += 8
        return data


    def stack_read(self, offset):
        return self.ql.unpack64(self.ql.mem.read(self.ql.reg.rsp + offset, 8))


    def stack_write(self, offset, data):
        return self.ql.mem.write(self.ql.reg.rsp + offset, self.ql.pack64(data))


    # get initialized unicorn engine
    def get_init_uc(self):
        uc = Uc(UC_ARCH_X86, UC_MODE_64)  
        return uc


    # set PC
    def set_pc(self, value):
        self.ql.reg.rip = value


    # get PC
    def get_pc(self):
        return self.ql.reg.rip


    # set stack pointer
    def set_sp(self, value):
        self.ql.reg.rsp = value


    # get stack pointer
    def get_sp(self):
        return self.ql.reg.rsp


    # get stack pointer register
    def get_name_sp(self):
        return reg_map_64["rsp"]


    # get pc register pointer
    def get_name_pc(self):
        return reg_map_64["rip"]


    # get register big, mostly use for x86  
    def get_reg_bit(self, register):
        if type(register) == str:
            register = self.get_reg_name(register)
        if register in ({v for k, v in reg_map_64.items()}):
            return 64
        else:
            return 32    


    def get_reg_table(self):
        registers_table = []
        adapter = {}
        adapter.update(reg_map_64)
        adapter.update(reg_map_misc)
        adapter.update(reg_map_st)
        registers = {k:v for k, v in adapter.items()}
        for reg in registers:
            registers_table += [reg]
        return registers_table


    # set register name
    def set_reg_name_str(self):
        pass  


    def get_reg_name_str(self, uc_reg): 
        adapter = {}
        adapter.update(reg_map_64)
        adapter.update(reg_map_misc)
        adapter.update(reg_map_st)
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
        adapter.update(reg_map_64)
        adapter.update(reg_map_misc)
        adapter.update(reg_map_st)

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
        ql.reg.write(UC_X86_REG_GDTR, (0, GDT_ADDR, GDT_LIMIT, 0x0))

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
    self.ql.reg.cs = self.gdtm.create_selector(3, QL_X86_S_GDT | QL_X86_S_PRIV_3)


def ql_x8664_register_cs(self):
    # While debugging the linux kernel segment, the cs segment was found on the sixth segment of gdt.
    self.gdtm.register_gdt_segment(6, 0, 0xfffffffffffff000, QL_X86_A_PRESENT | QL_X86_A_CODE | QL_X86_A_CODE_READABLE | QL_X86_A_PRIV_3 | QL_X86_A_EXEC | QL_X86_A_DIR_CON_BIT, QL_X86_S_GDT | QL_X86_S_PRIV_3)
    self.ql.reg.cs = self.gdtm.create_selector(6, QL_X86_S_GDT | QL_X86_S_PRIV_3)


def ql_x86_register_ds_ss_es(self):
    # TODO : The section permission here should be QL_X86_A_PRIV_3, but I do n’t know why it can only be set to QL_X86_A_PRIV_0.
    # While debugging the Linux kernel segment, I found that the three segments DS, SS, and ES all point to the same location in the GDT table. 
    # This position is the fifth segment table of GDT.
    self.gdtm.register_gdt_segment(5, 0, 0xfffff000, QL_X86_A_PRESENT | QL_X86_A_DATA | QL_X86_A_DATA_WRITABLE | QL_X86_A_PRIV_0 | QL_X86_A_DIR_CON_BIT, QL_X86_S_GDT | QL_X86_S_PRIV_0)
    self.ql.reg.ds = self.gdtm.create_selector(5, QL_X86_S_GDT | QL_X86_S_PRIV_0)
    self.ql.reg.ss = self.gdtm.create_selector(5, QL_X86_S_GDT | QL_X86_S_PRIV_0)
    self.ql.reg.es = self.gdtm.create_selector(5, QL_X86_S_GDT | QL_X86_S_PRIV_0)


def ql_x8664_register_ds_ss_es(self):
    # TODO : The section permission here should be QL_X86_A_PRIV_3, but I do n’t know why it can only be set to QL_X86_A_PRIV_0.
    # When I debug the Linux kernel, I find that only the SS is set to the fifth segment table, and the rest are not set.
    self.gdtm.register_gdt_segment(5, 0, 0xfffff000, QL_X86_A_PRESENT | QL_X86_A_DATA | QL_X86_A_DATA_WRITABLE | QL_X86_A_PRIV_0 | QL_X86_A_DIR_CON_BIT, QL_X86_S_GDT | QL_X86_S_PRIV_0)
    # ql.reg.write(UC_X86_REG_DS, ql.os.gdtm.create_selector(5, QL_X86_S_GDT | QL_X86_S_PRIV_0))
    self.ql.reg.ss = self.gdtm.create_selector(5, QL_X86_S_GDT | QL_X86_S_PRIV_0)
    # ql.reg.write(UC_X86_REG_ES, ql.os.gdtm.create_selector(5, QL_X86_S_GDT | QL_X86_S_PRIV_0))


def ql_x86_register_gs(self):
    self.gdtm.register_gdt_segment(15, GS_SEGMENT_ADDR, GS_SEGMENT_SIZE, QL_X86_A_PRESENT | QL_X86_A_DATA | QL_X86_A_DATA_WRITABLE | QL_X86_A_PRIV_3 | QL_X86_A_DIR_CON_BIT, QL_X86_S_GDT |  QL_X86_S_PRIV_3)
    self.ql.reg.gs = self.gdtm.create_selector(15, QL_X86_S_GDT | QL_X86_S_PRIV_0)


def ql_x86_register_fs(self):
    self.gdtm.register_gdt_segment(14, FS_SEGMENT_ADDR, FS_SEGMENT_SIZE, QL_X86_A_PRESENT | QL_X86_A_DATA | QL_X86_A_DATA_WRITABLE | QL_X86_A_PRIV_3 | QL_X86_A_DIR_CON_BIT, QL_X86_S_GDT |  QL_X86_S_PRIV_3)
    self.ql.reg.fs = self.gdtm.create_selector(14,  QL_X86_S_GDT |  QL_X86_S_PRIV_3)


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
