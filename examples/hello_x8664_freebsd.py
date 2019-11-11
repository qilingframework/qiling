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

from unicorn.x86_const import *

sys.path.append("..")
from qiling import *

def force_register_value(ql, address, size):
    rdi = ql.uc.reg_read(UC_X86_REG_RDI)
    r15 = ql.uc.reg_read(UC_X86_REG_R15)
    rax = ql.uc.reg_read(UC_X86_REG_RAX)
    rcx = ql.uc.reg_read(UC_X86_REG_RCX)
    #print (">>> rax: 0x%x, rcx: 0x%x, rdi: 0x%x, r15: 0x%x" % (rax, rcx, rdi, r15))

    
if __name__ == "__main__":
    ql = Qiling(["rootfs/x8664_freebsd/bin/x8664_hello_asm"], "rootfs/x8664_freebsd", output = "default")
    ql.hook_code(force_register_value)
    ql.run()
