#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
import sys
sys.path.append("..")
from qiling import *

def my_puts(ql, fn, next_pc):
    addr = ql.func_arg[0]
    print("puts(%s)" % ql.mem.string(addr))
    ql.reg.pc = next_pc

if __name__ == "__main__":
    ql = Qiling(["rootfs/x8664_linux/bin/x8664_hello"], "rootfs/x8664_linux")
    ql.set_api('puts', my_puts)
    ql.run()