#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework


from qiling.const import *
from ..arch import QlArch
from .vm.evm import QlArchEVMEmulator
from .hooks import monkeypath_core_hooks

class QlArchEVM(QlArch):
    type = QL_ARCH.EVM
    bits = 1

    def __init__(self, ql) -> None:
        super(QlArchEVM, self).__init__(ql)
        self.evm = QlArchEVMEmulator(self.ql)

        monkeypath_core_hooks(self.ql)

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

    @property
    def uc(self):
        return None

    @property
    def endian(self) -> QL_ENDIAN:
        return QL_ENDIAN.EL
