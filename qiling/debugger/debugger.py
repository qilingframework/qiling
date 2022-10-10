#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from qiling import Qiling


class QlDebugger:
    def __init__(self, ql: 'Qiling'):
        self.ql = ql

    def run(self):
        raise NotImplementedError
