#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import sys,unittest
sys.path.append("..")
from qiling import *
from qiling.exception import *
from test_elf import *
from test_macho import *
from test_posix import *
from test_qltool import *

if __name__ == "__main__":
    unittest.main()