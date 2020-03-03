#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import sys
from zipfile import ZipFile

sys.path.append("..")
from qiling import *

if __name__ == "__main__":
    zip_reader = ZipFile("shellcodes/win32_https_download.zip")
    with zip_reader.open('win32_https_download.bin', 'r', b'infected') as f:
        sc = f.read()
        ql = Qiling(shellcoder = sc, archtype = "x86", ostype = "windows",
                    rootfs="rootfs/x86_windows", output = "debug")
        ql.run()
