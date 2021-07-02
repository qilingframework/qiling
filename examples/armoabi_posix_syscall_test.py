#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_VERBOSE

def armoabi_le_syscall_test():
    path = ["rootfs/arm_linux/bin/posix_syscall_lsb.armoabi"]
    rootfs = "rootfs/arm_linux"
    ql = Qiling(path, rootfs, verbose = QL_VERBOSE.DEBUG)
    ql.run()

def armoabi_be_syscall_test():
    path = ["rootfs/armeb_linux/bin/posix_syscall_msb.armoabi"]
    rootfs = "rootfs/arm_linux"
    ql = Qiling(path, rootfs, verbose = QL_VERBOSE.DEBUG)
    ql.run()

if __name__ == "__main__":
    armoabi_le_syscall_test()
    armoabi_be_syscall_test()
