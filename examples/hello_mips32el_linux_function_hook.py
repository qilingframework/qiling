#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import sys

sys.path.append("..")
from qiling import *
from qiling.const import *

def my_puts_onenter(ql):
    addr = ql.os.function_arg[0]
    print("puts(%s)" % ql.mem.string(addr))
    return 2

def my_puts(ql):
    addr = ql.os.function_arg[0]
    print("puts(%s)" % ql.mem.string(addr))

def my_puts_onexit(ql):
    print("puts exit")
    return 2

if __name__ == "__main__":
    ql = Qiling(["rootfs/mips32el_linux/bin/mips32el_double_hello"], "rootfs/mips32el_linux", output="debug")
    ql.set_api('puts', my_puts_onenter, QL_INTERCEPT.ENTER)
    ql.set_api('puts', my_puts_onexit, QL_INTERCEPT.EXIT)
    ql.run()