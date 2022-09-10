#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework

from typing import MutableMapping, Optional

from qiling import Qiling
from qiling.const import QL_ARCH
from qiling.os.windows.api import PVOID
from qiling.os.windows.const import ERROR_INVALID_PARAMETER
from qiling.os.windows.fncc import CDECL

class Fiber:
    def __init__(self, idx: int, cb: Optional[int] = None):
        self.idx = idx
        self.data = 0
        self.cb = cb


class FiberManager:
    def __init__(self, ql: Qiling):
        self.fibers: MutableMapping[int, Fiber] = {}
        self.idx = 0
        self.ql = ql

    def alloc(self, cb: Optional[int] = None) -> int:
        idx = self.idx
        self.idx += 1

        self.fibers[idx] = Fiber(idx, cb)

        return idx

    def free(self, idx: int) -> bool:
        if idx not in self.fibers:
            self.last_error = ERROR_INVALID_PARAMETER
            return False

        fiber = self.fibers[idx]

        if fiber.cb is not None:
            self.ql.log.debug(f'Skipping callback function of fiber {fiber.idx} at {fiber.cb:#010x}')

            # TODO: should figure out how to emulate the fiber callback and still return to complete
            # the free api hook.
            #
            # details: normally the emulation flow is diverted by setting the architectural pc reg to
            # the desired address. however that would only take effect when all hooks for the current
            # address are done. here we want to call a native function and regain control once it is
            # done to complete the 'free' api that was started.
            #
            # one way to do that it to use 'ql.emu_start' and emulate the callback from its entry point
            # till it reaches its return address. that would indeed let us regain control and resume the
            # 'free' api hook we started here, but doing that will cause uc to abandon the current
            # emulation session -- effectively ending it. once the hooks for the current address are done,
            # the program will go idle.
            #
            # if we choose to emulate till 'ql.os.exit_point' instead, the program will continue but the
            # hook we are in will not resume and we will never "return" from it. using 'uc.context_save'
            # and 'uc.context_restore' to maintain the current emulation properties does not seem to help
            # here.
            #
            # we skip the fiber callback for now.

            # <SKIP>
            # self.ql.log.debug(f'Invoking callback function of fiber {fiber.idx} at {fiber.cb:#010x}')
            # self.__invoke_callback(fiber)
            # self.ql.log.debug(f'Callback function of fiber {fiber.idx} returned gracefully')
            # </SKIP>

        del self.fibers[idx]

        return True

    # TODO: this one is unused for now; see above
    def __invoke_callback(self, fiber: Fiber):
        assert fiber.cb is not None

        # we are in an api hook. extract the return address of the free
        # api to know where the callback should be returning to
        retaddr = self.ql.stack_read(0)

        # one PVOID arg, set to fiber data
        args = ((PVOID, fiber.data),)

        # set up call frame for callback
        fcall = self.ql.os.fcall_select(CDECL)
        fcall.call_native(fiber.cb, args, retaddr)

        # callback has to be invoked before returning from the free api
        self.ql.emu_start(fiber.cb, retaddr)

        # unwind call frame
        fcall.cc.unwind(len(args))

        # ms64 cc needs also to unwind the reserved shadow slots on the stack
        if self.ql.arch.type == QL_ARCH.X8664:
            self.ql.arch.regs.arch_sp += (4 * self.ql.arch.pointersize)

    def set(self, idx: int, data: int) -> bool:
        if idx not in self.fibers:
            self.last_error = ERROR_INVALID_PARAMETER
            return False

        self.fibers[idx].data = data

        return True

    def get(self, idx: int) -> int:
        if idx not in self.fibers:
            self.last_error = ERROR_INVALID_PARAMETER
            return 0

        return self.fibers[idx].data
