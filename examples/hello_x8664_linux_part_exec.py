#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_VERBOSE

if __name__ == "__main__":
    ql = Qiling(["rootfs/x8664_linux/bin/sleep_hello"], "rootfs/x8664_linux", verbose=QL_VERBOSE.DEFAULT)

    # load base address from profile file
    X64BASE = int(ql.profile.get("OS64", "load_address"), 16)

    # set execution starting and ending points
    begin_point = X64BASE + 0x109e
    end_point = X64BASE + 0x10bc

    ql.run(begin=begin_point, end=end_point)
