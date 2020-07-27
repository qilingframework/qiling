#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
import sys
sys.path.append("..")
from qiling import *
from qiling.const import *

def mem_crash(ql, access, addr, size, value):
    print("got crash")
    ql.mem.map(addr & ~0xfff, 0x1000)
    ql.mem.write(addr & ~0xfff, b'Q' * 0x1000)

if __name__ == "__main__":
    ql = Qiling(["rootfs/x8664_linux/bin/mem_invalid_access"], "rootfs/x8664_linux", output="debug")
    ql.hook_mem_invalid(mem_crash)
    ql.run()
