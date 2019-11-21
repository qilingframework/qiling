#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 


import sys

sys.path.append("..")
from qiling import *

    
if __name__ == "__main__":
    ql = Qiling(["rootfs/x8664_freebsd/bin/x8664_hello_asm"], "rootfs/x8664_freebsd", output = "default")
    ql.run()
