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
        self.running_module = None
        self.user_defined_api = {}
        self.user_defined_api_onenter = {}
        self.user_defined_api_onexit = {}
        self.PE_RUN = True
        self.heap = None # Will be initialized by the loader.
    
    def save(self):
        saved_state = super(QlOsUefi, self).save()
        saved_state['entry_point'] = self.entry_point
        return saved_state

    def restore(self, saved_state):
        super(QlOsUefi, self).restore(saved_state)
        self.entry_point = saved_state['entry_point']

    @staticmethod
    def notify_after_module_execution(ql, number_of_modules_left):
        return False
    
    @staticmethod
    def notify_before_module_execution(ql, module):
        ql.os.running_module = module
        return False

    def run(self):
        self.notify_before_module_execution(self.ql, self.running_module)
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


