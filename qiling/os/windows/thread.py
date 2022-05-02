#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import TYPE_CHECKING, cast

from qiling import Qiling
from qiling.const import QL_ARCH
from qiling.os.thread import QlThread

if TYPE_CHECKING:
    from qiling.os.windows.windows import QlOsWindows

class QlWindowsThread(QlThread):
    # static var
    ID = 0
    READY = 0
    RUNNING = 1
    TERMINATED = 2

    def __init__(self, ql: Qiling, status: int = 1, isFake: bool = False):
        super().__init__(ql)

        self.ql = ql
        self.id =  QlWindowsThread.ID
        QlWindowsThread.ID += 1
        self.status = status
        self.waitforthreads = []
        self.tls = {}
        self.tls_index = 0
        self.fake = isFake

    # create new thread
    def create(self, func_addr: int, func_params: int, status: int) -> int:
        os = cast('QlOsWindows', self.ql.os)

        # create new stack
        stack_size = 1024
        new_stack = os.heap.alloc(stack_size) + stack_size

        asize = self.ql.arch.pointersize
        context = self.ql.arch.regs.save()

        # set return address
        self.ql.mem.write_ptr(new_stack - asize, os.thread_manager.thread_ret_addr)

        # set parameters
        if self.ql.arch.type == QL_ARCH.X86:
            self.ql.mem.write_ptr(new_stack, func_params)
        elif self.ql.arch.type == QL_ARCH.X8664:
            context["rcx"] = func_params

        # set eip/rip, ebp/rbp, esp/rsp
        if self.ql.arch.type == QL_ARCH.X86:
            context["eip"] = func_addr
            context["ebp"] = new_stack - asize
            context["esp"] = new_stack - asize

        elif self.ql.arch.type == QL_ARCH.X8664:
            context["rip"] = func_addr
            context["rbp"] = new_stack - asize
            context["rsp"] = new_stack - asize

        self.saved_context = context
        self.status = status

        return self.id

    def suspend(self) -> None:
        self.saved_context = self.ql.arch.regs.save()

    def resume(self) -> None:
        self.ql.arch.regs.restore(self.saved_context)
        self.status = QlWindowsThread.RUNNING

    def stop(self) -> None:
        self.status = QlWindowsThread.TERMINATED

    def is_stop(self) -> bool:
        return self.status == QlWindowsThread.TERMINATED

    def waitfor(self, thread: 'QlWindowsThread') -> None:
        self.waitforthreads.append(thread)

    def has_waitfor(self) -> bool:
        return any(not thread.is_stop() for thread in self.waitforthreads)


# Simple Thread Manager
class QlWindowsThreadManagement(QlThread):
    TIME_SLICE = 10

    def __init__(self, ql: Qiling, os: 'QlOsWindows', cur_thread: QlWindowsThread):
        super().__init__(ql)

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

            self.do_schedule()

        ql.hook_code(__thread_scheduler)

    def append(self, thread: QlWindowsThread):
        self.threads.append(thread)

    def need_schedule(self):
        return self.cur_thread.is_stop() or (self.icount % QlWindowsThreadManagement.TIME_SLICE) == 0

    def do_schedule(self) -> None:
        if self.need_schedule():
            # if there is less than one thread, this loop won't run
            for i in range(1, len(self.threads)):
                next_id = (self.cur_thread.id + i) % len(self.threads)
                next_thread = self.threads[next_id]

                # find next thread
                if next_thread.status == QlWindowsThread.RUNNING and not next_thread.has_waitfor():
                    if not self.cur_thread.is_stop():
                        self.cur_thread.suspend()

                    next_thread.resume()
                    self.cur_thread = next_thread

                    break
