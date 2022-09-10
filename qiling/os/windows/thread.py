#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import Enum
from typing import TYPE_CHECKING, cast

from qiling import Qiling
from qiling.const import QL_ARCH, QL_HOOK_BLOCK
from qiling.os.thread import QlThread

if TYPE_CHECKING:
    from qiling.os.windows.windows import QlOsWindows

class THREAD_STATUS(Enum):
    READY = 0
    RUNNING = 1
    TERMINATED = 2

class QlWindowsThread(QlThread):
    # static var
    ID = 0

    def __init__(self, ql: Qiling, status: THREAD_STATUS = THREAD_STATUS.RUNNING):
        super().__init__(ql)

        self.ql = ql
        self.id =  QlWindowsThread.ID
        QlWindowsThread.ID += 1
        self.status = status
        self.waitforthreads = []
        self.tls = {}
        self.tls_index = 0

    # create a new thread with context
    @classmethod
    def create(cls, ql: Qiling, stack_size: int, func_addr: int, func_params: int, status: THREAD_STATUS) -> 'QlWindowsThread':
        os = cast('QlOsWindows', ql.os)

        thread = cls(ql, status)

        # create new stack
        new_stack = os.heap.alloc(stack_size) + stack_size

        asize = ql.arch.pointersize
        context = ql.arch.regs.save()

        # set return address
        ql.mem.write_ptr(new_stack - asize, os.thread_manager.thread_ret_addr)

        # set parameters
        if ql.arch.type == QL_ARCH.X86:
            ql.mem.write_ptr(new_stack, func_params)
        elif ql.arch.type == QL_ARCH.X8664:
            context["rcx"] = func_params

        # set eip/rip, ebp/rbp, esp/rsp
        if ql.arch.type == QL_ARCH.X86:
            context["eip"] = func_addr
            context["ebp"] = new_stack - asize
            context["esp"] = new_stack - asize

        elif ql.arch.type == QL_ARCH.X8664:
            context["rip"] = func_addr
            context["rbp"] = new_stack - asize
            context["rsp"] = new_stack - asize

        thread.saved_context = context

        return thread

    def suspend(self) -> None:
        self.saved_context = self.ql.arch.regs.save()

    def resume(self) -> None:
        self.ql.arch.regs.restore(self.saved_context)
        self.status = THREAD_STATUS.RUNNING

    def stop(self) -> None:
        self.status = THREAD_STATUS.TERMINATED

    def is_stop(self) -> bool:
        return self.status == THREAD_STATUS.TERMINATED

    def waitfor(self, thread: 'QlWindowsThread') -> None:
        self.waitforthreads.append(thread)

    def has_waitfor(self) -> bool:
        return any(not thread.is_stop() for thread in self.waitforthreads)


# Simple Thread Manager
class QlWindowsThreadManagement:
    TIME_SLICE = 10

    def __init__(self, ql: Qiling, os: 'QlOsWindows', cur_thread: QlWindowsThread):
        self.ql = ql

        # main thread
        self.cur_thread = cur_thread
        self.threads = [self.cur_thread]
        self.icount = 0
        self.thread_ret_addr = os.heap.alloc(8)

        # write nop to thread_ret_addr
        ql.mem.write(self.thread_ret_addr, b'\x90' * 8)

        def __thread_scheduler(ql: Qiling, address: int, size: int):
            if ql.arch.regs.arch_pc == self.thread_ret_addr:
                self.cur_thread.stop()
            else:
                self.icount += 1

            switched = self.do_schedule()

            # in case another thread was resumed, all remaining hooks should be skipped to prevent them
            # from running with the new thread's context.

            return QL_HOOK_BLOCK if switched else 0

        ql.hook_code(__thread_scheduler)

    def append(self, thread: QlWindowsThread):
        self.threads.append(thread)

    def do_schedule(self) -> bool:
        need_schedule = self.cur_thread.is_stop() or (self.icount % QlWindowsThreadManagement.TIME_SLICE) == 0
        switched = False

        if need_schedule:
            # if there is less than one thread, this loop won't run
            for i in range(1, len(self.threads)):
                next_id = (self.cur_thread.id + i) % len(self.threads)
                next_thread = self.threads[next_id]

                # find next thread
                if next_thread.status == THREAD_STATUS.RUNNING and not next_thread.has_waitfor():
                    if not self.cur_thread.is_stop():
                        self.cur_thread.suspend()

                    next_thread.resume()
                    self.cur_thread = next_thread

                    switched = True
                    break

        return switched
