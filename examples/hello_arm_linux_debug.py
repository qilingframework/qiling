#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
import sys
sys.path.append("..")
from qiling import *


def run_sandbox(path, rootfs, output):
    ql = Qiling(path, rootfs, output = output)
    ql.debug = True
    ql.debug_stop = True
    ql.run()


if __name__ == "__main__":
    #run_sandbox(["rootfs/arm_linux/bin/arm_hello_static"], "rootfs/arm_linux", None)
    #run_sandbox(["rootfs/arm_linux/bin/arm_hello_static"], "rootfs/arm_linux", "disasm")
    run_sandbox(["rootfs/arm_linux/bin/arm_hello_static"], "rootfs/arm_linux", "debug")
