#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_VERBOSE

def run_sandbox(path, rootfs, verbose):
    ql = Qiling(path, rootfs, verbose = verbose)
    ql.debugger = "qdb" # enable qdb without options
    # ql.debugger = "qdb::rr" # switch on record and replay with rr
    # ql.debugger = "qdb:0x1030c" # enable qdb and setup breakpoin at 0x1030c
    ql.run()

if __name__ == "__main__":
    run_sandbox(["rootfs/arm_linux/bin/arm_hello"], "rootfs/arm_linux", QL_VERBOSE.DEBUG)
