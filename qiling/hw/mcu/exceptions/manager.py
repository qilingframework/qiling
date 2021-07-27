#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

class ExceptionManager:
    def __init__(self, ql):
        self.ql = ql

    def send_interrupt(self, *args, **kw):
        raise NotImplemented

    def exec_interrupt(self):
        raise NotImplemented
