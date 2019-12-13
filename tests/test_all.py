#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import sys,unittest
sys.path.append("..")
from qiling import *
from qiling.exception import *
from test_elf import *
from test_pe_reactos import *
from test_macho import *
from test_qltool import *

class AllTest(unittest.TestCase):
    ELFTest()
    #REACTOSPETest()
    MACHOTest()
    QltoolTest()


if __name__ == "__main__":
    unittest.main()
