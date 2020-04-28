#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
import sys
sys.path.append("..")
from qiling import *

def my_puts(ql, fn, ori_val):
    rdi = ql.register('RDI')
    print("puts(%s)" % ql.mem.string(rdi))
    ql.reg.pc = ori_val

if __name__ == "__main__":
    ql = Qiling(["rootfs/x8664_linux/bin/x8664_hello"], "rootfs/x8664_linux")
    ql.os.add_function_hook('puts', my_puts)
    ql.run()