#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

# This sample code enables GDB server at localhost:9999 (default settings)

import sys
sys.path.append("..")
from qiling import *


def test_gdb(path, rootfs):
    ql = Qiling(path, rootfs, output="off")

    # Enable debugger to listen at localhost address, default port 9999
    # ql.debugger = True

    # You can also customize address & port or type of debugging server
    ql.debugger = ":9999"  # GDB server listens to 0.0.0.0:9999
    # ql.debugger = "127.0.0.1:9999"  # GDB server listens to 127.0.0.1:9999
    # ql.debugger = "gdb:127.0.0.1:9999"  # GDB server listens to 127.0.0.1:9999
    # ql.debugger = "idapro:127.0.0.1:9999"  # IDApro server listens to 127.0.0.1:9999
    # ql.debugger = "qdb" # attach Qdb and pause at entry point, only works for MIPS for now

    # Emulate
    ql.run()  

if __name__ == "__main__":
    # test_gdb(["rootfs/x86_linux/bin/x86_hello"], "rootfs/x86_linux")
    test_gdb(["rootfs/x8664_linux/bin/x8664_hello"], "rootfs/x8664_linux")
