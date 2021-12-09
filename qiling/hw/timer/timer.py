#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


from qiling.core import Qiling
from qiling.hw.peripheral import QlPeripheral


class QlTimerPeripheral(QlPeripheral):
    def __init__(self, ql: Qiling, label: str):
        super().__init__(ql, label)

        self._ratio = 1

    def set_ratio(self, ratio):
        self._ratio = ratio

    @property
    def ratio(self):
        return self._ratio

    @ratio.setter
    def ratio(self, value):
        self.set_ratio(value)
