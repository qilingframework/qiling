#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
#
# LAU kaijern (xwings) <kj@qiling.io>
# NGUYEN Anh Quynh <aquynh@gmail.com>
# DING tianZe (D1iv3) <dddliv3@gmail.com>
# SUN bowen (w1tcher) <w1tcher.bupt@gmail.com>
# CHEN huitao (null) <null@qiling.io>
# YU tong (sp1ke) <spikeinhouse@gmail.com>

import sys
sys.path.append("..")
from qiling import *

def run_sandbox(path, rootfs):
    ql = Qiling(path, rootfs, output = "debug")
    # if 0x555555566260 is being written, exit
    ql.set_exit(0x555555566260)
    ql.run()


if __name__ == "__main__":
    run_sandbox(["rootfs/arm64_linux/bin/arm64_hello"], "rootfs/arm64_linux")
