#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("..")
from qiling import *

if __name__ == "__main__":
    ql = Qiling(["rootfs/8086/dos/HI.DOS_COM"], "rootfs/8086/dos", output="disasm")
    ql.run()
