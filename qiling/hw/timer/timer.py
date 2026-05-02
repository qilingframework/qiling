#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import ctypes

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

    def save(self):
        return (self._ratio, bytes(self.instance))

    def restore(self, data):
        self._ratio, raw = data
        ctypes.memmove(ctypes.addressof(self.instance), raw, len(raw))
