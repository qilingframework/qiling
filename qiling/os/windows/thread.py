#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from unicorn.x86_const import *
from qiling.exception import *
from qiling.os.thread import *
from .utils import *


def thread_scheduler(ql, address, size):
    if ql.reg.pc == ql.os.thread_manager.THREAD_RET_ADDR:
        ql.os.thread_manager.cur_thread.stop()
        ql.os.thread_manager.do_schedule()
    else:
        ql.os.thread_manager.ins_count += 1
        ql.os.thread_manager.do_schedule()


# Simple Thread Manager
class QlWindowsThreadManagement(QlThread):
    TIME_SLICE = 10

    def __init__(self, ql, cur_thread):
        super(QlWindowsThreadManagement, self).__init__(ql)
        self.ql = ql
        # main thread
        self.cur_thread = cur_thread
        self.threads = [self.cur_thread]
        self.ins_count = 0
        self.THREAD_RET_ADDR = self.ql.os.heap.mem_alloc(8)
        # write nop to THREAD_RET_ADDR
        self.ql.mem.write(self.THREAD_RET_ADDR, b"\x90"*8)
        self.ql.hook_code(thread_scheduler)

    def append(self, thread):
        self.threads.append(thread)

    def need_schedule(self):
        return self.cur_thread.is_stop() or self.ins_count %  QlWindowsThreadManagement.TIME_SLICE == 0

    def do_schedule(self):
        if self.cur_thread.is_stop() or self.ins_count %  QlWindowsThreadManagement.TIME_SLICE == 0:
            if len(self.threads) <= 1:
                return
            else:
                for i in range(1, len(self.threads)):
                    next_id = (self.cur_thread.id + i) % len(self.threads)
                    next_thread = self.threads[next_id]
                    # find next thread
                    if next_thread.status == QlWindowsThread.RUNNING and (not next_thread.has_waitfor()):
                        if self.cur_thread.is_stop():
                            pass
                        else:
                            self.cur_thread.suspend()
                        next_thread.resume()
                        self.cur_thread = next_thread
                        break


class QlWindowsThread(QlThread):
    # static var
    ID = 0
    READY = 0
    RUNNING = 1
    TERMINATED = 2

    def __init__(self, ql, status=1, isFake=False):
        super(QlWindowsThread, self).__init__(ql)
        self.ql = ql
        self.id =  QlWindowsThread.ID
        QlWindowsThread.ID += 1
        self.status = status
        self.waitforthreads = []
        self.tls = {}
        self.tls_index = 0
        self.fake = isFake

    # create new thread
    def create(self, func_addr, func_params, status):
        # create new stack
        stack_size = 1024
        new_stack = self.ql.os.heap.mem_alloc(stack_size) + stack_size
        
        # FIXME : self.ql.os this is ugly, should be self.os.thread_manager
        if self.ql.archtype == QL_ARCH.X86:
            self.ql.mem.write(new_stack - 4, self.ql.pack32(self.ql.os.thread_manager.THREAD_RET_ADDR))
            self.ql.mem.write(new_stack, self.ql.pack32(func_params))
        elif self.ql.archtype == QL_ARCH.X8664:
            self.ql.mem.write(new_stack - 8, self.ql.pack64(self.ql.os.thread_manager.THREAD_RET_ADDR))
            self.ql.mem.write(new_stack, self.ql.pack64(func_params))

        # set eip, ebp, esp
        self.saved_context = self.ql.reg.store()

        if self.ql.archtype == QL_ARCH.X86:
            self.saved_context["EIP"] = func_addr
            self.saved_context["EBP"] = new_stack - 4
            self.saved_context["ESP"] = new_stack - 4
        elif self.ql.archtype == QL_ARCH.X8664:
            self.saved_context["RIP"] = func_addr
            self.saved_context["RBP"] = new_stack - 8
            self.saved_context["RSP"] = new_stack - 8

        self.status = status
        return self.id

    def suspend(self):
        self.saved_context = self.ql.reg.store()

    def resume(self):
        self.ql.reg.restore(self.saved_context)
        self.status = QlWindowsThread.RUNNING

    def stop(self):
        self.status = QlWindowsThread.TERMINATED

    def is_stop(self):
        return self.status == QlWindowsThread.TERMINATED

    def waitfor(self, thread):
        self.waitforthreads.append(thread)

    def has_waitfor(self):
        for each_thread in self.waitforthreads:
            if not each_thread.is_stop():
                return True
        return False
