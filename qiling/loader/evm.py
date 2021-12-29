#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 


from qiling.const import *
from qiling.core import Qiling
from .loader import QlLoader


class QlLoaderEVM(QlLoader):
    def __init__(self, ql:Qiling):
        super(QlLoaderEVM, self).__init__(ql)
        self.ql = ql
        
        if self.ql.code is None:
            with open(self.ql.path) as f:
                self.code = f.read()
        else:
            self.code = ql.code

    def run(self):
        pass
