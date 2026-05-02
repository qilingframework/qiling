#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from zipfile import ZipFile

import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE

if __name__ == "__main__":
    with ZipFile("shellcodes/win32_https_download.zip") as zip_reader:
        with zip_reader.open('win32_https_download.bin', 'r', b'infected') as f:
            sc = f.read()

    ql = Qiling(code=sc, archtype=QL_ARCH.X86, ostype=QL_OS.WINDOWS, rootfs="rootfs/x86_windows", verbose=QL_VERBOSE.DEBUG)
    ql.run()
