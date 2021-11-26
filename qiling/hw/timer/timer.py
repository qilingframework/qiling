#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


from qiling.core import Qiling
from qiling.hw.peripheral import QlPeripheral


class QlTimerPeripheral(QlPeripheral):
    def __init__(self, ql: Qiling, label: str):
        super().__init__(ql, label)

        self.ratio = 1

    def set_ratio(self, ratio):
        self.ratio = ratio
