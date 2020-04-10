#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 


import os
from qiling.os.utils import *
from qiling.const import *
from qiling.os.const import *

class QlOs:
    def __init__(self, ql):
        self.ql = ql

        # define analysis enviroment profile
        if not self.ql.profile:
            self.profile = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".." ,"profiles", ql_ostype_convert_str(self.ql.ostype) + ".ql")

        if self.ql.archbit == 32:
            self.QL_EMU_END = QL_ARCHBIT32_EMU_END
        elif self.ql.archbit == 64:
            self.QL_EMU_END = QL_ARCHBIT64_EMU_END           

