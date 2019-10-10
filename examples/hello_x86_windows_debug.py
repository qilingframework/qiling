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

def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs, output = "debug")
    ql.run()


if __name__ == "__main__":
    my_sandbox(["rootfs/x86_windows/bin/x86_hello.exe"], "rootfs/x86_windows")
