#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import ctypes
import types
import struct
from unicorn import *
from unicorn.x86_const import *
from qiling.const import *
from qiling.os.os import QlOs

class QlOsUefi(QlOs):
    def __init__(self, ql):
        super(QlOsUefi, self).__init__(ql)
        self.ql = ql
        self.entry_point = 0

    def run(self):
        self.setup_output()
        try:
            if self.ql.shellcoder:
                self.PE_RUN = False
                self.ql.uc.emu_start(self.ql.code_address, self.ql.code_address + len(self.ql.shellcoder))
            else:
                self.PE_RUN = True
                path, self.entry_point, pe = self.ql.modules.pop(0)
                # workaround, the debugger sets the breakpoint before the module is loaded.
                if hasattr(self.ql.remotedebugsession ,'gdb'):
                    self.ql.remotedebugsession.gdb.bp_insert(self.entry_point)
                self.ql.stack_push(self.ql.end_of_execution_ptr)
                self.ql.reg.rdx = self.ql.system_table_ptr
                self.ql.nprint(f'Running from 0x{self.entry_point:x} of {path}')
            self.ql.uc.emu_start(self.entry_point, self.exit_point, 100000*1000)
        except UcError:
            raise

        if self.ql.internal_exception is not None:
            raise self.ql.internal_exception
