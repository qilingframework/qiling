#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
# A Simple Windows Clipboard Simulation

from unicorn import *
from unicorn.x86_const import *


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
            self.ql.os.last_error = 0x57  # ERROR_INVALID_PARAMETER
            return 0
        else:
            fiber = self.fibers[idx]
            if fiber.cb:
                self.ql.dprint(0, "Skipping emulation of callback function 0x%X for fiber 0x%X" % (fiber.cb, fiber.idx))
                """
                ret_addr = self.ql.register(UC_X86_REG_RIP + 6 ) #FIXME, use capstone to get addr of next instr?

                # Write Fls data to memory to be accessed by cb
                addr = self.ql.heap.mem_alloc(self.ql.pointersize)
                data = fiber.data.to_bytes(self.ql.pointersize, byteorder='little')
                self.ql.mem.write(addr, data)

                # set up params and return address then jump to callback
                if self.ql.pointersize == 8:
                    self.ql.register(UC_X86_REG_RCX, addr)
                else:
                    self.ql.stack_push(ret_addr)
                self.ql.stack_push(ret_addr)
                self.ql.dprint(0,"Jumping to callback @ 0x%X" % fiber.cb)
                self.ql.register(UC_X86_REG_RIP, fiber.cb)
                # All of this gets overwritten by the rest of the code in fncc.py
                # Not sure how to actually make unicorn emulate the callback function due to that
                """
            else:
                del self.fibers[idx]
                return 1

    def set(self, idx, data):
        if idx not in self.fibers:
            self.ql.os.last_error = 0x57  # ERROR_INVALID_PARAMETER
            return 0
        else:
            self.fibers[idx].data = data
            return 1

    def get(self, idx):
        if idx not in self.fibers:
            self.ql.os.last_error = 0x57  # ERROR_INVALID_PARAMETER
            return 0
        else:
            return self.fibers[idx].data
