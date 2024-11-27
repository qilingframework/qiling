#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from typing import Any, Callable

class Hook:
    def __init__(self, callback: Callable, user_data: Any = None, begin: int = 1, end: int = 0):
        self.callback = callback
        self.user_data = user_data
        self.begin = begin
        self.end = end

    def bound_check(self, pc: int, size: int = 1) -> bool:
        return (self.end < self.begin) or (self.begin <= pc <= self.end) or (self.begin <= (pc + size - 1) <= self.end)


    def check(self, *args) -> bool:
        return True


    def call(self, ql, *args):
        if self.user_data is None:
            return self.callback(ql, *args)

        return self.callback(ql, *args, self.user_data)


class HookAddr(Hook):
    def __init__(self, callback, address: int, user_data=None):
        super().__init__(callback, user_data, address, address)

        self.addr = address


class HookIntr(Hook):
    def __init__(self, callback, intno: int, user_data=None):
        super().__init__(callback, user_data, 0, -1)

        self.intno = intno


    def check(self, intno: int) -> bool:
        return (intno < 0) or (self.intno == intno)


class HookRet:
    def __init__(self, ql, hook_type: int, hook_obj: Hook):
        self.type = hook_type
        self.obj = hook_obj

        self.__remove = ql.hook_del

    def remove(self) -> None:
        self.__remove(self)
