#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 


from qiling.const import *
from qiling.core import Qiling

from .loader import QlLoader
from intelhex import IntelHex


class QlLoaderMCU(QlLoader):
    def __init__(self, ql:Qiling):
        super(QlLoaderMCU, self).__init__(ql)
        
        self.ihexfile = IntelHex(self.argv[0])
        
    def run(self):
        for begin, end in self.ihexfile.segments():
            self.ql.mem.write(begin, self.ihexfile.tobinstr(begin, end - 1))
