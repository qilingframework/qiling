#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("..")

from qiling import Qiling

if __name__ == "__main__":
    ql = Qiling(["rootfs/x86_windows/bin/NtQuerySystemInformation.exe"], "rootfs/x86_windows", libcache=True)
    ql.run()
