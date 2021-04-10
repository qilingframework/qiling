#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#
import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_VERBOSE

def mem_crash(ql: Qiling, access: int, address: int, size: int, value: int):
    print(f'got crash')

    PAGE_SIZE = 0x1000
    aligned = address & ~(PAGE_SIZE - 1)

    # map the entire page containing the invalid address and fill it with 'Q's
    ql.mem.map(aligned, PAGE_SIZE)
    ql.mem.write(aligned, b'Q' * PAGE_SIZE)

if __name__ == "__main__":
    ql = Qiling(["rootfs/x8664_linux/bin/mem_invalid_access"], "rootfs/x8664_linux", verbose=QL_VERBOSE.DEBUG)

    ql.hook_mem_invalid(mem_crash)
    ql.run()
