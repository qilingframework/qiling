#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
from unicorn import *
from unicorn.x86_const import *
from struct import pack
from .arch import Arch
from qiling.arch.filetype import *

QL_X86_F_GRANULARITY = 0x8
QL_X86_F_PROT_32 = 0x4
QL_X86_F_LONG = 0x2
QL_X86_F_AVAILABLE = 0x1

QL_X86_A_PRESENT = 0x80

QL_X86_A_PRIV_3 = 0x60
QL_X86_A_PRIV_2 = 0x40
QL_X86_A_PRIV_1 = 0x20
QL_X86_A_PRIV_0 = 0x0

QL_X86_A_CODE = 0x10
QL_X86_A_DATA = 0x10
QL_X86_A_TSS = 0x0
QL_X86_A_GATE = 0x0
QL_X86_A_EXEC = 0x8

QL_X86_A_DATA_WRITABLE = 0x2
QL_X86_A_CODE_READABLE = 0x2
QL_X86_A_DIR_CON_BIT = 0x4

QL_X86_S_GDT = 0x0
QL_X86_S_LDT = 0x4
QL_X86_S_PRIV_3 = 0x3
QL_X86_S_PRIV_2 = 0x2
QL_X86_S_PRIV_1 = 0x1
QL_X86_S_PRIV_0 = 0x0

QL_X86_GDT_ADDR = 0x3000
QL_X86_GDT_LIMIT = 0x1000
QL_X86_GDT_ENTRY_SIZE = 0x8

QL_X86_GDT_ADDR_PADDING = 0xe0000000
QL_X8664_GDT_ADDR_PADDING = 0x7effffff00000000


class X86(Arch):
    def __init__(self, ql):
        super(X86, self).__init__(ql)


    def stack_push(self, value):
        SP = self.ql.uc.reg_read(UC_X86_REG_ESP)
        SP -= 4
        self.ql.uc.mem_write(SP, self.ql.pack32(value))
        self.ql.uc.reg_write(UC_X86_REG_ESP, SP)
        return SP

    def stack_pop(self):
        SP = self.ql.uc.reg_read(UC_X86_REG_ESP)
        data = self.ql.unpack32(self.ql.uc.mem_read(SP, 4))
        self.ql.uc.reg_write(UC_X86_REG_ESP, SP + 4)
        return data


    def stack_read(self, offset):
        SP = self.ql.uc.reg_read(UC_X86_REG_ESP)
        return self.ql.unpack32(self.ql.uc.mem_read(SP + offset, 4))


    def stack_write(self, offset, data):
        SP = self.ql.uc.reg_read(UC_X86_REG_ESP)
        return self.ql.uc.mem_write(SP + offset, self.ql.pack32(data))


    # set PC
    def set_pc(self, value):
        self.ql.uc.reg_write(UC_X86_REG_EIP, value)


    # get PC
    def get_pc(self):
        return self.ql.uc.reg_read(UC_X86_REG_EIP)


    # set stack pointer
    def set_sp(self, value):
        self.ql.uc.reg_write(UC_X86_REG_ESP, value)


    # get stack pointer
    def get_sp(self):
        return self.ql.uc.reg_read(UC_X86_REG_ESP)


class X8664(Arch):
    def __init__(self, ql):
        super(X8664, self).__init__(ql)


    def stack_push(self, value):
        SP = self.ql.uc.reg_read(UC_X86_REG_RSP)
        SP -= 8
        self.ql.uc.mem_write(SP, self.ql.pack64(value))
        self.ql.uc.reg_write(UC_X86_REG_RSP, SP)
        return SP

    def stack_pop(self):
        SP = self.ql.uc.reg_read(UC_X86_REG_RSP)
        data = self.ql.unpack64(self.ql.uc.mem_read(SP, 8))
        self.ql.uc.reg_write(UC_X86_REG_RSP, SP + 8)
        return data


    def stack_read(self, offset):
        SP = self.ql.uc.reg_read(UC_X86_REG_RSP)
        return self.ql.unpack64(self.ql.uc.mem_read(SP + offset, 8))


    def stack_write(self, offset, data):
        SP = self.ql.uc.reg_read(UC_X86_REG_RSP)
        return self.ql.uc.mem_write(SP + offset, self.ql.pack64(data))

    # set PC
    def set_pc(self, value):
        self.ql.uc.reg_write(UC_X86_REG_RIP, value)


    # get PC
    def get_pc(self):
        return self.ql.uc.reg_read(UC_X86_REG_RIP)


    # set stack pointer
    def set_sp(self, value):
        self.ql.uc.reg_write(UC_X86_REG_RSP, value)


    # get stack pointer
    def get_sp(self):
        return self.ql.uc.reg_read(UC_X86_REG_RSP)


def ql_x86_setup_gdt_segment(ql, GDT_ADDR, GDT_LIMIT, seg_reg, index, SEGMENT_ADDR, SEGMENT_SIZE, SPORT, RPORT, GDTTYPE):
    # create segment index
    def create_selector(idx, flags):
        to_ret = flags
        to_ret |= idx << 3
        return to_ret

    # create a GDT entry for a segment
    def create_gdt_entry(base, limit, access, flags):
        to_ret = limit & 0xffff
        to_ret |= (base & 0xffffff) << 16
        to_ret |= (access & 0xff) << 40
        to_ret |= ((limit >> 16) & 0xf) << 48
        to_ret |= (flags & 0xff) << 52
        to_ret |= ((base >> 24) & 0xff) << 56
        return pack('<Q', to_ret)

    # map GDT table
    if ql.ostype == QL_LINUX and GDTTYPE == "DS":
        ql.dprint("[+] OS Type: %d" % (ql.ostype))
        ql.uc.mem_map(GDT_ADDR, GDT_LIMIT)
    
    if ql.ostype == QL_WINDOWS and GDTTYPE == "FS":
        ql.uc.mem_map(GDT_ADDR, GDT_LIMIT)
        ql.uc.mem_map(SEGMENT_ADDR, SEGMENT_SIZE)

    if ql.ostype == QL_FREEBSD and GDTTYPE == "FS":
        if not ql.shellcoder:
            if ql.arch == QL_X86:
                GDT_ADDR = GDT_ADDR + QL_X86_GDT_ADDR_PADDING
            elif ql.arch == QL_X8664:
                GDT_ADDR = GDT_ADDR + QL_X8664_GDT_ADDR_PADDING
        ql.dprint ("[+] GDT_ADDR is 0x%x" % (GDT_ADDR))
        ql.uc.mem_map(GDT_ADDR, GDT_LIMIT)
    
    if ql.ostype == QL_MACOS and GDTTYPE == "DS":
        if not ql.shellcoder:
            if ql.arch == QL_X86:
                GDT_ADDR = GDT_ADDR + QL_X86_GDT_ADDR_PADDING
            elif ql.arch == QL_X8664:
                GDT_ADDR = GDT_ADDR + QL_X8664_GDT_ADDR_PADDING

        ql.dprint ("[+] GDT_ADDR is 0x%x" % (GDT_ADDR))
        ql.uc.mem_map(GDT_ADDR, GDT_LIMIT)
    
    # create GDT entry, then write GDT entry into GDT table
    gdt_entry = create_gdt_entry(SEGMENT_ADDR, SEGMENT_SIZE, SPORT, QL_X86_F_PROT_32)
    ql.uc.mem_write(GDT_ADDR + (index << 3), gdt_entry)

    #ql.nprint(ql.arch)
    # setup GDT by writing to GDTR
    ql.uc.reg_write(UC_X86_REG_GDTR, (0, GDT_ADDR, GDT_LIMIT, 0x0))

    # create segment index, point segment register to this selector
    selector = create_selector(index, RPORT)
    ql.dprint("[+] SET_THREAD_AREA selector : 0x%x" % selector)
    ql.uc.reg_write(seg_reg, selector)


def ql_x86_setup_gdt_segment_ds(ql):
    ql_x86_setup_gdt_segment(ql, QL_X86_GDT_ADDR, QL_X86_GDT_LIMIT, UC_X86_REG_DS, 16, 0, 0xfffff000, QL_X86_A_PRESENT | QL_X86_A_DATA | QL_X86_A_DATA_WRITABLE | QL_X86_A_PRIV_3 | QL_X86_A_DIR_CON_BIT, QL_X86_S_GDT | QL_X86_S_PRIV_3, "DS")


def ql_x86_setup_gdt_segment_cs(ql):
    ql_x86_setup_gdt_segment(ql, QL_X86_GDT_ADDR, QL_X86_GDT_LIMIT, UC_X86_REG_CS, 17, 0, 0xfffff000, QL_X86_A_PRESENT | QL_X86_A_CODE | QL_X86_A_CODE_READABLE | QL_X86_A_PRIV_3 | QL_X86_A_EXEC | QL_X86_A_DIR_CON_BIT, QL_X86_S_GDT | QL_X86_S_PRIV_3, "CS")


def ql_x86_setup_gdt_segment_ss(ql):
    ql_x86_setup_gdt_segment(ql, QL_X86_GDT_ADDR, QL_X86_GDT_LIMIT, UC_X86_REG_SS, 18, 0, 0xfffff000, QL_X86_A_PRESENT | QL_X86_A_DATA | QL_X86_A_DATA_WRITABLE | QL_X86_A_PRIV_0 | QL_X86_A_DIR_CON_BIT, QL_X86_S_GDT | QL_X86_S_PRIV_0, "SS")


def ql_x86_setup_syscall_set_thread_area(ql, base, limit):
    ql_x86_setup_gdt_segment(ql, QL_X86_GDT_ADDR, QL_X86_GDT_LIMIT, UC_X86_REG_GS, 12, base, limit, QL_X86_A_PRESENT | QL_X86_A_DATA | QL_X86_A_DATA_WRITABLE | QL_X86_A_PRIV_3 | QL_X86_A_DIR_CON_BIT, QL_X86_S_GDT | QL_X86_S_PRIV_3, "STA")


def ql_x86_setup_gdt_segment_fs(ql, FS_SEGMENT_ADDR, FS_SEGMENT_SIZE):
    ql_x86_setup_gdt_segment(ql, QL_X86_GDT_ADDR, QL_X86_GDT_LIMIT, UC_X86_REG_FS, 14, FS_SEGMENT_ADDR, FS_SEGMENT_SIZE, QL_X86_A_PRESENT | QL_X86_A_DATA | QL_X86_A_DATA_WRITABLE | QL_X86_A_PRIV_3 | QL_X86_A_DIR_CON_BIT, QL_X86_S_GDT |  QL_X86_S_PRIV_3, "FS")


def ql_x86_setup_gdt_segment_gs(ql, GS_SEGMENT_ADDR, GS_SEGMENT_SIZE):
    ql_x86_setup_gdt_segment(ql, QL_X86_GDT_ADDR, QL_X86_GDT_LIMIT, UC_X86_REG_GS, 15, GS_SEGMENT_ADDR, GS_SEGMENT_SIZE, QL_X86_A_PRESENT | QL_X86_A_DATA | QL_X86_A_DATA_WRITABLE | QL_X86_A_PRIV_3 | QL_X86_A_DIR_CON_BIT, QL_X86_S_GDT |  QL_X86_S_PRIV_3, "GS")


def ql_x8664_setup_gdt_segment_ds(ql):
    ql_x86_setup_gdt_segment(ql, QL_X86_GDT_ADDR, QL_X86_GDT_LIMIT, UC_X86_REG_DS, 16, 0, 0xfffffffffffff000, QL_X86_A_PRESENT | QL_X86_A_DATA | QL_X86_A_DATA_WRITABLE | QL_X86_A_PRIV_3 | QL_X86_A_DIR_CON_BIT, QL_X86_S_GDT | QL_X86_S_PRIV_3, "DS")


def ql_x8664_setup_gdt_segment_cs(ql):
    ql_x86_setup_gdt_segment(ql, QL_X86_GDT_ADDR, QL_X86_GDT_LIMIT, UC_X86_REG_CS, 17, 0, 0xfffffffffffff000, QL_X86_A_PRESENT | QL_X86_A_CODE | QL_X86_A_CODE_READABLE | QL_X86_A_PRIV_3 | QL_X86_A_EXEC | QL_X86_A_DIR_CON_BIT, QL_X86_S_GDT | QL_X86_S_PRIV_3, "CS")


def ql_x8664_setup_gdt_segment_ss(ql):
    ql_x86_setup_gdt_segment(ql, QL_X86_GDT_ADDR, QL_X86_GDT_LIMIT, UC_X86_REG_SS, 18, 0, 0xfffffffffffff000, QL_X86_A_PRESENT | QL_X86_A_DATA | QL_X86_A_DATA_WRITABLE | QL_X86_A_PRIV_0 | QL_X86_A_DIR_CON_BIT, QL_X86_S_GDT | QL_X86_S_PRIV_0, "SS")


def ql_x8664_setup_gdt_segment_fs(ql, FS_SEGMENT_ADDR, FS_SEGMENT_SIZE):
    ql_x86_setup_gdt_segment(ql, QL_X86_GDT_ADDR, QL_X86_GDT_LIMIT, UC_X86_REG_FS, 14, FS_SEGMENT_ADDR, FS_SEGMENT_SIZE, QL_X86_A_PRESENT | QL_X86_A_DATA | QL_X86_A_DATA_WRITABLE | QL_X86_A_PRIV_3 | QL_X86_A_DIR_CON_BIT, QL_X86_S_GDT |  QL_X86_S_PRIV_3, "FS")
