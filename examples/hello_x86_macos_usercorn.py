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

from capstone import *
from unicorn.x86_const import *

sys.path.append("..")
from qiling import *

md = Cs(CS_ARCH_X86, CS_MODE_32)

def dump_everything(uc, address, size, user_data):
    buf = ql.uc.mem_read(address, size)
    for i in md.disasm(buf, address):
        print(":: 0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
    eax = uc.reg_read(UC_X86_REG_EAX)
    ebx = uc.reg_read(UC_X86_REG_EBX)
    ecx = uc.reg_read(UC_X86_REG_ECX)
    edx = uc.reg_read(UC_X86_REG_EDX)
    edi = uc.reg_read(UC_X86_REG_EDI)
    esi = uc.reg_read(UC_X86_REG_ESI)
    ebp = uc.reg_read(UC_X86_REG_EBP)
    esp = uc.reg_read(UC_X86_REG_ESP)
    ds = uc.reg_read(UC_X86_REG_DS)
    gs = uc.reg_read(UC_X86_REG_GS)
    ss = uc.reg_read(UC_X86_REG_SS)
    cs = uc.reg_read(UC_X86_REG_CS)
    print(">>> EAX= 0x%x, EBX= 0x%x, ECX= 0x%x, EDX= 0x%x, EDI= 0x%x, ESI= 0x%x, EBP= 0x%x, ESP= 0x%x, DS= 0x%x, GS= 0x%x, SS= 0x%x, CS= 0x%x " % (eax, ebx, ecx, edx, edi, esi, ebp, esp,ds,gs,ss,cs))
    print ("")

if __name__ == "__main__":
    ql = Qiling(["rootfs/x86_macos/bin/x86_hello_usercorn"], "rootfs/x86_macos", output = "default")
    # ql.hook_code(dump_everything)
    ql.run()
