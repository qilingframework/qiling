#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_INTERCEPT, QL_VERBOSE
from qiling.os.linux.syscall_nums import SYSCALL_NR

def write_onenter(ql: Qiling, arg1, arg2, arg3, *args):
    print("enter write syscall!")
    ql.reg.rsi = arg2 + 1
    ql.reg.rdx = arg3 - 1

def write_onexit(ql: Qiling, arg1, arg2, arg3, *args):
    print("exit write syscall!")
    ql.reg.rax = arg3 + 1

if __name__ == "__main__":
    ql = Qiling(["rootfs/x8664_linux/bin/x8664_hello"], "rootfs/x8664_linux", verbose=QL_VERBOSE.DEBUG)

    ql.set_syscall(SYSCALL_NR.write, write_onenter, QL_INTERCEPT.ENTER)
    ql.set_syscall(SYSCALL_NR.write, write_onexit, QL_INTERCEPT.EXIT)
    ql.run()
