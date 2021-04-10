#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_VERBOSE

def stopatkillerswtich(ql: Qiling):
    print(f'killerswtch found')
    ql.emu_stop()

if __name__ == "__main__":
    ql = Qiling(["rootfs/x86_windows/bin/wannacry.bin"], "rootfs/x86_windows", verbose=QL_VERBOSE.DEBUG)
    ql.hook_address(stopatkillerswtich, 0x40819a)
    ql.run()
