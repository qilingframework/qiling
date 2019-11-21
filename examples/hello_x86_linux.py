#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import sys
sys.path.append("..")
from qiling import *

def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs)
    ql.run()


if __name__ == "__main__":
    my_sandbox(["rootfs/x86_linux/bin/x86_hello"], "rootfs/x86_linux")
