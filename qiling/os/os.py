#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from qiling.const import *
import os
from qiling.os.utils import *

class QlOs:
    def __init__(self, ql):
        self.ql = ql

        # define analysis enviroment profile
        if not self.ql.profile:
            self.profile = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".." ,"profiles", ql_ostype_convert_str(self.ql.ostype) + ".ql")
        else:    
            self.profile = os.path.join(self.ql.cur_pathname, self.ql.profile)
