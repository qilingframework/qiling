#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
import sys
sys.path.append("..")
from qiling import *
from qiling.const import *

def write_onenter(ql, arg1, arg2, arg3, *args):
    print("enter write syscall!")
    ql.reg.rsi = arg2 + 1
    ql.reg.rdx = arg3 - 1

def write_onexit(ql, arg1, arg2, arg3, *args):
    print("exit write syscall!")
    ql.reg.rax = arg3 + 1

if __name__ == "__main__":
    ql = Qiling(["rootfs/x8664_linux/bin/x8664_hello"], "rootfs/x8664_linux", output="debug")
    # ql.set_api('puts', my_puts)
    ql.set_syscall(1, write_onenter, QL_INTERCEPT.ENTER)
    ql.set_syscall(1, write_onexit, QL_INTERCEPT.EXIT)
    ql.run()
