#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_VERBOSE

if __name__ == "__main__":
    ql = Qiling(["rootfs/mips32el_linux/bin/mips32el_hello_static"], "rootfs/mips32el_linux", verbose=QL_VERBOSE.DEBUG)
    ql.run()
