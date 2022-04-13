#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.const import QL_OS
from qiling.os.os import QlOs

class QlOsMcu(QlOs):
    type = QL_OS.MCU

    def run(self):
        pass
