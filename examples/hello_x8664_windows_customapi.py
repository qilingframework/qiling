#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import sys
sys.path.append("..")
from qiling import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *

@winapi(x86=X86_CDECL, x8664=X8664_FASTCALL, params={
    "str": STRING
})
def my_puts(ql, address, params):
    ret = 0
    ql.nprint("\n+++++++++\nmy 64bit random Windows API\n+++++++++\n")
    string = params["str"]
    ret = len(string)
    return ret


def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs, output = "debug")
    ql.set_winapi("puts", my_puts)
    ql.run()

if __name__ == "__main__":
    my_sandbox(["rootfs/x8664_windows/bin/x8664_hello.exe"], "rootfs/x8664_windows")
