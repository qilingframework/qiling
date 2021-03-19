#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework

from qiling import Qiling
from qiling.os.windows.const import ERROR_INVALID_PARAMETER

class Fiber:
    def __init__(self, idx, cb=None):
        self.idx = idx
        self.data = 0
        self.cb = cb


class FiberManager:
    def __init__(self, ql: Qiling):
        self.fibers = {}
        self.idx = 0
        self.ql = ql

    def alloc(self, cb=None):
        rtn = self.idx
        self.fibers[self.idx] = Fiber(self.idx, cb=cb)
        self.idx += 1
        return rtn

    def free(self, idx):
        if idx in self.fibers:
            fiber = self.fibers[idx]

            if fiber.cb:
                self.ql.log.debug(f'Skipping emulation of callback function {fiber.cb:#x} for fiber {fiber.idx:#x}')

                """
                ret_addr = self.ql.reg.read(UC_X86_REG_RIP + 6 ) #FIXME, use capstone to get addr of next instr?

                # Write Fls data to memory to be accessed by cb
                addr = self.ql.os.heap.alloc(self.ql.pointersize)
                data = fiber.data.to_bytes(self.ql.pointersize, byteorder='little')
                self.ql.mem.write(addr, data)

                # set up params and return address then jump to callback
                if self.ql.pointersize == 8:
                    self.ql.reg.write(UC_X86_REG_RCX, addr)
                else:
                    self.ql.stack_push(ret_addr)
                self.ql.stack_push(ret_addr)
                self.ql.log.debug("Jumping to callback @ 0x%X" % fiber.cb)
                self.ql.reg.write(UC_X86_REG_RIP, fiber.cb)
                # All of this gets overwritten by the rest of the code in fncc.py
                # Not sure how to actually make unicorn emulate the callback function due to that
                """

            else:
                del self.fibers[idx]
                return 1

        self.last_error = ERROR_INVALID_PARAMETER
        return 0

    def set(self, idx, data):
        if idx in self.fibers:
            self.fibers[idx].data = data
            return 1

        self.last_error = ERROR_INVALID_PARAMETER
        return 0

    def get(self, idx):
        if idx in self.fibers:
            return self.fibers[idx].data

        self.last_error = ERROR_INVALID_PARAMETER
        return 0
