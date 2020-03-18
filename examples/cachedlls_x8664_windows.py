#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
import sys
from qiling import *
sys.path.append("..")

if __name__ == "__main__":
    ql = Qiling(
        ["rootfs/x8664_windows/bin/x8664_hello.exe"],
        "rootfs/x8664_windows",
        libcache=True,
        output="default"
    )
    ql.run()
