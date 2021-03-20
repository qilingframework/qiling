#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("..")

from qiling import Qiling

def run_sandbox(path, rootfs):
    ql = Qiling(path, rootfs, output = "debug")
    ql.run(end=0x7fffb7e98af4)

if __name__ == "__main__":
    run_sandbox(["rootfs/arm64_linux/bin/arm64_hello"], "rootfs/arm64_linux")
