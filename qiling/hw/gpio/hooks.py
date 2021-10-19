#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


class GpioHooks:
    def __init__(self, ql, pin_num):
        self.ql = ql
        self.hook_set_func   = [lambda: ...] * pin_num
        self.hook_reset_func = [lambda: ...] * pin_num

    def hook_set(self, pin, func):
        self.hook_set_func[pin] = func

    def hook_reset(self, pin, func):
        self.hook_reset_func[pin] = func

    def hook_del_set(self, pin):
        self.hook_set_func[pin] = lambda: ...

    def hook_del_reset(self, pin):
        self.hook_reset_func[pin] = lambda: ...
