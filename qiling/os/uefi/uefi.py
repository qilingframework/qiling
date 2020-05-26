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
        self.user_defined_api = {}
        self.notify_immediately = False
        self.PE_RUN = True
    
    def run(self):
        if self.ql.exit_point is not None:
            self.exit_point = self.ql.exit_point
        
        if  self.ql.entry_point  is not None:
            self.ql.loader.entry_point = self.ql.entry_point

        try:
            self.ql.emu_start(self.ql.loader.entry_point, self.exit_point, self.ql.timeout, self.ql.count)
        except UcError:
            self.emu_error()
            raise

        if self.ql.internal_exception is not None:
            raise self.ql.internal_exception

