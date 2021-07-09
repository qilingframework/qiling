#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework

from ..const import QL_ARCH
from .evm import QlArchEVM
from .arch import QlArch


class QlArchEngine(QlArch):
    def __init__(self, ql) -> None:
        self.ql = ql
        if ql.archtype == QL_ARCH.EVM:
            self.evm = QlArchEVM(ql)

    def run(self, code):
        if self.ql.archtype == QL_ARCH.EVM:
            return self.evm.run(code)

    def stack_push(self, value):
        pass

    def stack_pop(self):
        pass

    def stack_write(self, value, data):
        pass

    def stack_read(self, value):
        pass
