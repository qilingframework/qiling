#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import unittest

from test_elf import *
from test_riscv import *
from test_qltool import *

from test_elf_hwcap_projection import *

if __name__ == "__main__":
    unittest.main()
