#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn import UcError

from qiling.os.os import QlOs

class QlOsMcu(QlOs):
    def __init__(self, ql):
        super(QlOsMcu, self).__init__(ql)

    def run(self):
        pass
