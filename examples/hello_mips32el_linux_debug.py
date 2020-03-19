#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import sys, string, random
from qiling import *
sys.path.append("..")

if __name__ == "__main__":
    ql = Qiling(["rootfs/mips32el_linux/bin/mips32el_hello_static"], "rootfs/mips32el_linux", output = "debug")
    ql.run()
