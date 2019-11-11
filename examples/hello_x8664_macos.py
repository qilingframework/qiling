#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
#
# LAU kaijern (xwings) <kj@qiling.io>
# NGUYEN Anh Quynh <aquynh@gmail.com>
# DING tianZe (D1iv3) <dddliv3@gmail.com>
# SUN bowen (w1tcher) <w1tcher.bupt@gmail.com>
# CHEN huitao (null) <null@qiling.io>
# YU tong (sp1ke) <spikeinhouse@gmail.com>
import sys
sys.path.append("..")
from qiling import *

from capstone import *
from unicorn.x86_const import *

sys.path.append("..")

md = Cs(CS_ARCH_X86, CS_MODE_64)


breakOn = False

def dump_everything(ql, address, size, user_data):
    global breakOn
    flag = False
    buf = ql.uc.mem_read(address, size)
    for i in md.disasm(buf, address):
        print("PC :: 0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        if i.address - 0x3000000000000000 in user_data:
            flag = True
    eax = uc.reg_read(UC_X86_REG_RAX)
    ebx = uc.reg_read(UC_X86_REG_RBX)
    ecx = uc.reg_read(UC_X86_REG_RCX)
    edx = uc.reg_read(UC_X86_REG_RDX)
    edi = uc.reg_read(UC_X86_REG_RDI)
    esi = uc.reg_read(UC_X86_REG_RSI)
    ebp = uc.reg_read(UC_X86_REG_RBP)
    esp = uc.reg_read(UC_X86_REG_RSP)
    ds = uc.reg_read(UC_X86_REG_DS)
    gs = uc.reg_read(UC_X86_REG_GS)
    ss = uc.reg_read(UC_X86_REG_SS)
    cs = uc.reg_read(UC_X86_REG_CS)

    if flag:
        breakOn = True

    if breakOn:
        print(">>> RAX= 0x%lx, RBX= 0x%lx, RCX= 0x%lx, RDX= 0x%lx, RDI= 0x%lx, RSI= 0x%lx, RBP= 0x%lx, RSP= 0x%lx, DS= 0x%lx, GS= 0x%lx, SS= 0x%lx, CS= 0x%lx " % (eax, ebx, ecx, edx, edi, esi, ebp, esp,ds,gs,ss,cs))
        stack_info = uc.mem_read(esp, 20)
        # print(stack_info)
        print ("")
        c = input()
        if c == 'c':
            breakOn = False

if __name__ == "__main__":
    ql = Qiling(["rootfs/x8664_macos/bin/x8664_hello"], "rootfs/x8664_macos", output = "debug")
    break_point = [
        # 0x1276,
        # 0x4320
        # 0x0182A,
        0x5B7B,
    ]
    # ql.hook_code(dump_everything, break_point)
    ql.run()
