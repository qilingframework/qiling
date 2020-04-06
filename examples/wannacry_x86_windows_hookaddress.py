#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
import sys
sys.path.append("..")
from qiling import *

def stopatkillerswtich(ql):
    print("killerswtch found")
    ql.uc.emu_stop()

if __name__ == "__main__":
    ql = Qiling(["samples_anyrun/ransom/GandCrab502.bin"], "examples/rootfs/x86_windows", output = "debug")
    ql.hook_address(stopatkillerswtich, 0x40860f)
    ql.run()
