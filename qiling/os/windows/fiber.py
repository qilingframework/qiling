#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
# A Simple Windows Clipboard Simulation

class Fiber:
    def __init__(self, idx, cb=None):
        self.idx = idx
        self.data = 0
        self.cb = cb

class FiberManager:
    def __init__(self, ql):
        self.fibers = {}
        self.idx = 0
        self.ql = ql

    def alloc(self, cb=None):
        rtn = self.idx
        self.fibers[self.idx] = Fiber(self.idx, cb=cb)
        self.idx += 1
        return rtn
    
    def free(self, idx):
        if idx not in self.fibers:
            ql.last_error = 0x57 #ERROR_INVALID_PARAMETER
            return 0
        else:
            fiber = self.fibers[idx]
            if fiber.cb:
                self.ql.dprint("Calling callback function 0x%X for fiber 0x%X" % (fiber.cb, fiber.idx))
            else:
                del self.fibers[idx]
                return 1

    def set(self, idx, data):
        if idx not in self.fibers:
            ql.last_error = 0x57 #ERROR_INVALID_PARAMETER
            return 0
        else:
            self.fibers[idx].data = data
            return 1

    def get(self, idx):
        if idx not in self.fibers:
            ql.last_error = 0x57 #ERROR_INVALID_PARAMETER
            return 0
        else:
            return self.fibers[idx].data
