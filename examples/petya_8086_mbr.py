#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import sys
sys.path.append("..")
from qiling import *
from qiling.os.disk import QlDisk

def code_hook(ql, addr, arg):
    print(hex(addr))


if __name__ == "__main__":
    ql = Qiling(["rootfs/8086_dos/petya/mbr.bin"], "rootfs/8086_dos", output="debug")
    ql.hook_code(code_hook)
    # infected disk
    ql.add_fs_mapper(0x80, QlDisk("rootfs/8086_dos/petya/out_1M.raw", 0x80))
    ql.run()