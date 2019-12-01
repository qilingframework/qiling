#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)
#
# Nguyen Hong Quang (quangnh89) <quangnh89@gmail.com>

import sys

sys.path.append("..")
from qiling import *

if __name__ == "__main__":
    sc = open("shellcodes/win32_https_download.bin",'rb').read()
    ql = Qiling(shellcoder = sc, archtype = "x86", ostype = "windows", rootfs="rootfs/x86_windows", output = "debug")
    ql.run()
