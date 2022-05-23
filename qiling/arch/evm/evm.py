#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework


import types

from qiling.arch.arch import QlArch
from qiling.arch.evm.hooks import monkeypatch_core_hooks
from qiling.arch.evm.vm.evm import QlArchEVMEmulator
from qiling.arch.evm.vm.message import Message
from qiling.const import *

class QlArchEVM(QlArch):
    type = QL_ARCH.EVM
    bits = 1

    def __init__(self, ql) -> None:
        super(QlArchEVM, self).__init__(ql)
        self.evm = QlArchEVMEmulator(self.ql)

        monkeypatch_core_hooks(self.ql)
        monkeypatch_core_methods(self.ql)

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


def __evm_run(self, code: Message):
    return self.arch.run(code)

def monkeypatch_core_methods(ql):
    """Monkeypatch core methods for evm
    """

    ql.run = types.MethodType(__evm_run, ql)
