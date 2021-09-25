#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework


from qiling.const import *
from ..arch import QlArch
from .vm.evm import QlArchEVMEmulator


class QlArchEVM(QlArch):
    def __init__(self, ql) -> None:
        super(QlArchEVM, self).__init__(ql)
        self.evm = QlArchEVMEmulator(self.ql)

    def run(self, msg):
        return self.evm.vm.execute_message(msg)

    def stack_push(self, value):
        return None

    def stack_pop(self):
        return None

    def stack_read(self, offset):
        return None

    def stack_write(self, offset, data):
        return None

    def get_init_uc(self):
        return None
