#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_VERBOSE

def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs, verbose=QL_VERBOSE.DEBUG, multithread=True)
    ql.run()

if __name__ == "__main__":
    my_sandbox(["rootfs/arm64_linux/bin/arm64_multithreading"], "rootfs/arm64_linux")
