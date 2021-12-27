#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


class GpioHooks:
    def __init__(self, ql, pin_num):
        self.ql = ql
        self.hook_set_func   = [None] * pin_num
        self.hook_reset_func = [None] * pin_num

    def hook_set(self, pin, func, *args, **kwargs):
        self.hook_set_func[pin] = (func, args, kwargs)

    def hook_reset(self, pin, func, *args, **kwargs):
        self.hook_reset_func[pin] = (func, args, kwargs)

    def hook_del_set(self, pin):
        self.hook_set_func[pin] = None

    def hook_del_reset(self, pin):
        self.hook_reset_func[pin] = None

    def call_hook_set(self, pin):
        if self.hook_set_func[pin]:
            func, args, kwargs = self.hook_set_func[pin]
            func(*args, **kwargs)

    def call_hook_reset(self, pin):
        if self.hook_reset_func[pin]:
            func, args, kwargs = self.hook_reset_func[pin]
            func(*args, **kwargs)