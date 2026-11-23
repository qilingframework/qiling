#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import unittest

from test_elf import *
from test_riscv import *
from test_qltool import *
from test_syscall_pread64_errno import Pread64ErrnoTests

if __name__ == "__main__":
    unittest.main()
