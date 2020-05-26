#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import sys
sys.path.append("..")
from qiling import *

if __name__ == "__main__":
    ql = Qiling(["rootfs/x8664_linux/bin/sleep_hello"], "rootfs/x8664_linux", output= "default")
    X64BASE = int(ql.profile.get("OS64", "load_address"), 16)
    begin_point = X64BASE + 0x109e
    end_point = X64BASE + 0x10bc
    ql.run(begin = begin_point, end = end_point)