#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 


from unicorn.arm64_const import *

import sys
sys.path.append("..")
from qiling import *

def run_sandbox(path, rootfs):
    ql = Qiling(path, rootfs)
    ql.run()


if __name__ == "__main__":
    run_sandbox(["rootfs/arm64_linux/bin/arm64_hello"], "rootfs/arm64_linux")
