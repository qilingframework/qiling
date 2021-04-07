#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

class Hook:
    def __init__(self, callback, user_data=None, begin=1, end=0):
        self.callback = callback
        self.user_data = user_data
        self.begin = begin
        self.end = end

    def bound_check(self, pc, size=1):
        return (self.end < self.begin) or (self.begin <= pc <= self.end) or (self.begin <= (pc + size - 1) <= self.end)


    def check(self, *args):
        return True
    

    def call(self, ql, *args):
        if self.user_data == None:
            return self.callback(ql, *args)
        return self.callback(ql, *args, self.user_data)


class HookAddr(Hook):
    def __init__(self, callback, address, user_data=None):
        super(HookAddr, self).__init__(callback, user_data, address, address)
        self.addr = address
    

    def call(self, ql, *args):
        if self.user_data == None:
            return self.callback(ql)
        return self.callback(ql, self.user_data)


class HookIntr(Hook):
    def __init__(self, callback, intno, user_data=None):
        super(HookIntr, self).__init__(callback, user_data, 0, -1)
        self.intno = intno
    

    def check(self, ql, intno):
        ql.log.debug("[+] Received Interupt: %i Hooked Interupt: %i" % (intno, self.intno))
        if intno < 0 or self.intno == intno:
            return True
        return False


class HookRet:
    def __init__(self, ql, t, h):
        self._ql = ql
        self._t = t
        self._h = h
    

    def remove(self):
        self._ql.hook_del(self._t, self._h)