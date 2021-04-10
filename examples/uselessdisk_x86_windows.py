#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_VERBOSE

if __name__ == "__main__":
    ql = Qiling(["rootfs/x86_windows/bin/UselessDisk.bin"], "rootfs/x86_windows", verbose=QL_VERBOSE.DEBUG)
    ql.run()
