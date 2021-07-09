#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys

sys.path.append("..")

from qiling import Qiling

if __name__ == "__main__":
    ql = Qiling(["rootfs/arm_qnx/bin/hello"], "rootfs/arm_qnx")
    ql.run()
