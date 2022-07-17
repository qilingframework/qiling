#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_INTERCEPT
from qiling.os.linux.syscall_nums import SYSCALL_NR

def write_onenter(ql: Qiling, fd: int, buf: int, count: int):
    print("enter write syscall!")

    ql.arch.regs.rsi = buf + 1
    ql.arch.regs.rdx = count - 1

def write_onexit(ql: Qiling, fd: int, buf: int, count: int, retval: int):
    print("exit write syscall!")

    ql.arch.regs.rax = count + 1

if __name__ == "__main__":
    ql = Qiling(["rootfs/x8664_linux/bin/x8664_hello"], "rootfs/x8664_linux")

    ql.os.set_syscall(SYSCALL_NR.write, write_onenter, QL_INTERCEPT.ENTER)
    ql.os.set_syscall(SYSCALL_NR.write, write_onexit, QL_INTERCEPT.EXIT)

    ql.run()
