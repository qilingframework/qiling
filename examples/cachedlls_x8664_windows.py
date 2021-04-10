#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_VERBOSE

if __name__ == "__main__":
    ql = Qiling(["rootfs/x8664_windows/bin/x8664_hello.exe"], "rootfs/x8664_windows", verbose=QL_VERBOSE.DEFAULT, libcache=True)
    ql.run()
