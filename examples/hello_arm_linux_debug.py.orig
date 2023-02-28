#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_VERBOSE

if __name__ == "__main__":
    ql = Qiling([r'rootfs/arm_linux/bin/arm_hello'], r'rootfs/arm_linux', verbose=QL_VERBOSE.DEBUG)

    ql.debugger = "qdb" # enable qdb without options

    # other possible alternatives:
    # ql.debugger = "qdb::rr" # switch on record and replay with rr
    # ql.debugger = "qdb:0x1030c" # enable qdb and setup breakpoin at 0x1030c

    ql.run()
