#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import sys
sys.path.append("..")
from qiling import *
from qiling.os.disk import QlDisk

if __name__ == "__main__":
    ql = Qiling(["rootfs/8086_dos/petya/mbr.bin"], 
                 "rootfs/8086_dos",
                 console=False, 
                 output="debug", 
                 log_dir=".")
    # Note:
    # This image is only intended for PoC since the core petya code resides in the
    # sepecific sectors of a harddisk. It doesn't contain any data, either encryted
    # or unencrypted.
    ql.add_fs_mapper(0x80, QlDisk("rootfs/8086_dos/petya/out_1M.raw", 0x80))
    ql.run()