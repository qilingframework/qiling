#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import unittest

from test_elf import *
from test_riscv import *
from test_qltool import *

from test_syscall_munmap_shared_eof import *

if __name__ == "__main__":
    unittest.main()
