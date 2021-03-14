#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling


class QlDebugger():
    def __init__(self, ql:Qiling):
        self.ql = ql

    def dbg_start(self):
        pass

    def dbg_run(self, begin_addr=None, end_addr=None):
        self.ql.emu_start(begin=begin_addr, end=end_addr)
    
    def dbg_step(self):
        pass

    def dbg_continue(self):
        pass

    def dbg_set_breakpoint(self):
        pass
