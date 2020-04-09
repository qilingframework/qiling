#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from unicorn.x86_const import *
from qiling.os.windows.utils import *
from qiling.exception import *


def thread_scheduler(ql, address, size):
    if ql.pc == ql.thread_manager.THREAD_RET_ADDR:
        ql.thread_manager.current_thread.stop()
        ql.thread_manager.do_schedule()
    else:
        ql.thread_manager.ins_count += 1
        ql.thread_manager.do_schedule()


class Context:
    def __init__(self, ql):
        self.ql = ql

    def save(self):
        if self.ql.archtype == QL_X86:
            self.edi = self.ql.register(UC_X86_REG_EDI)
            self.esi = self.ql.register(UC_X86_REG_ESI)
            self.ebx = self.ql.register(UC_X86_REG_EBX)
            self.edx = self.ql.register(UC_X86_REG_EDX)
            self.ecx = self.ql.register(UC_X86_REG_ECX)
            self.eax = self.ql.register(UC_X86_REG_EAX)
            self.ebp = self.ql.register(UC_X86_REG_EBP)
            self.eip = self.ql.register(UC_X86_REG_EIP)
            self.esp = self.ql.register(UC_X86_REG_ESP)
            self.eflags = self.ql.register(UC_X86_REG_EFLAGS)
        elif self.ql.archtype == QL_X8664:
            self.rdi = self.ql.register(UC_X86_REG_RDI)
            self.rsi = self.ql.register(UC_X86_REG_RSI)
            self.rbx = self.ql.register(UC_X86_REG_RBX)
            self.rdx = self.ql.register(UC_X86_REG_RDX)
            self.rcx = self.ql.register(UC_X86_REG_RCX)
            self.rax = self.ql.register(UC_X86_REG_RAX)
            self.rbp = self.ql.register(UC_X86_REG_RBP)
            self.rip = self.ql.register(UC_X86_REG_RIP)
            self.rsp = self.ql.register(UC_X86_REG_RSP)
            self.r8 = self.ql.register(UC_X86_REG_R8)
            self.r9 = self.ql.register(UC_X86_REG_R9)
            self.r10 = self.ql.register(UC_X86_REG_R10)
            self.r11 = self.ql.register(UC_X86_REG_R11)
            self.r12 = self.ql.register(UC_X86_REG_R12)
            self.r13 = self.ql.register(UC_X86_REG_R13)
            self.r14 = self.ql.register(UC_X86_REG_R14)
            self.r15 = self.ql.register(UC_X86_REG_R15)
            self.eflags = self.ql.register(UC_X86_REG_EFLAGS)
        else:
            raise QlErrorArch("[!] unknown ql.arch")

    def restore(self):
        if self.ql.archtype == QL_X86:
            self.ql.register(UC_X86_REG_EDI, self.edi)
            self.ql.register(UC_X86_REG_ESI, self.esi)
            self.ql.register(UC_X86_REG_EBX, self.ebx)
            self.ql.register(UC_X86_REG_EDX, self.edx)
            self.ql.register(UC_X86_REG_ECX, self.ecx)
            self.ql.register(UC_X86_REG_EAX, self.eax)
            self.ql.register(UC_X86_REG_EBP, self.ebp)
            self.ql.register(UC_X86_REG_EIP, self.eip)
            self.ql.register(UC_X86_REG_ESP, self.esp)
            self.ql.register(UC_X86_REG_EFLAGS, self.eflags)
        elif self.ql.archtype == QL_X8664:
            self.ql.register(UC_X86_REG_RDI, self.rdi)
            self.ql.register(UC_X86_REG_RSI, self.rsi)
            self.ql.register(UC_X86_REG_RBX, self.rbx)
            self.ql.register(UC_X86_REG_RDX, self.rdx)
            self.ql.register(UC_X86_REG_RCX, self.rcx)
            self.ql.register(UC_X86_REG_RAX, self.rax)
            self.ql.register(UC_X86_REG_RBP, self.rbp)
            self.ql.register(UC_X86_REG_RIP, self.rip)
            self.ql.register(UC_X86_REG_RSP, self.rsp)
            self.ql.register(UC_X86_REG_R8, self.r8)
            self.ql.register(UC_X86_REG_R9, self.r9)
            self.ql.register(UC_X86_REG_R10, self.r10)
            self.ql.register(UC_X86_REG_R11, self.r11)
            self.ql.register(UC_X86_REG_R12, self.r12)
            self.ql.register(UC_X86_REG_R13, self.r13)
            self.ql.register(UC_X86_REG_R14, self.r14)
            self.ql.register(UC_X86_REG_R15, self.r15)
            self.ql.register(UC_X86_REG_EFLAGS, self.eflags)
        else:
            raise QlErrorArch("[!] unknown ql.arch")


# A Simple Thread Manager
class ThreadManager:
    TIME_SLICE = 10

    def __init__(self, ql, current_thread):
        self.ql = ql
        # main thread
        self.current_thread = current_thread
        self.threads = [self.current_thread]
        self.ins_count = 0
        self.THREAD_RET_ADDR = self.ql.heap.mem_alloc(8)
        # write nop to THREAD_RET_ADDR
        self.ql.mem.write(self.THREAD_RET_ADDR, b"\x90"*8)
        self.ql.hook_code(thread_scheduler)

    def append(self, thread):
        self.threads.append(thread)

    def need_schedule(self):
        return self.current_thread.is_stop() or self.ins_count % ThreadManager.TIME_SLICE == 0

    def do_schedule(self):
        if self.current_thread.is_stop() or self.ins_count % ThreadManager.TIME_SLICE == 0:
            if len(self.threads) <= 1:
                return
            else:
                for i in range(1, len(self.threads)):
                    next_id = (self.current_thread.id + i) % len(self.threads)
                    next_thread = self.threads[next_id]
                    # find next thread
                    if next_thread.status == Thread.RUNNING and (not next_thread.has_waitfor()):
                        if self.current_thread.is_stop():
                            pass
                        else:
                            self.current_thread.suspend()
                        next_thread.resume()
                        self.current_thread = next_thread
                        break


class Thread:
    # static var
    ID = 0
    READY = 0
    RUNNING = 1
    TERMINATED = 2

    def __init__(self, ql, status=1, isFake=False):
        self.ql = ql
        self.id = Thread.ID
        Thread.ID += 1
        self.context = Context(ql)
        self.status = status
        self.waitforthreads = []
        self.tls = {}
        self.tls_index = 0
        self.fake = isFake

    # create new thread
    def create(self, func_addr, func_params, status):
        # create new stack
        stack_size = 1024
        new_stack = self.ql.heap.mem_alloc(stack_size) + stack_size

        if self.ql.archtype == QL_X86:
            self.ql.mem.write(new_stack - 4, self.ql.pack32(self.ql.thread_manager.THREAD_RET_ADDR))
            self.ql.mem.write(new_stack, self.ql.pack32(func_params))
        elif self.ql.archtype == QL_X8664:
            self.ql.mem.write(new_stack - 8, self.ql.pack64(self.ql.thread_manager.THREAD_RET_ADDR))
            self.ql.mem.write(new_stack, self.ql.pack64(func_params))

        # set eip, ebp, esp
        self.context.save()
        if self.ql.archtype == QL_X86:
            self.context.eip = func_addr
            self.context.ebp = new_stack - 4
            self.context.esp = new_stack - 4
        elif self.ql.archtype == QL_X8664:
            self.context.rip = func_addr
            self.context.rbp = new_stack - 8
            self.context.rsp = new_stack - 8

        self.status = status
        return self.id

    def suspend(self):
        self.context.save()
        # self.context.print("save")

    def resume(self):
        self.context.restore()
        # self.context.print("restore")
        self.status = Thread.RUNNING

    def stop(self):
        self.status = Thread.TERMINATED

    def is_stop(self):
        return self.status == Thread.TERMINATED

    def waitfor(self, thread):
        self.waitforthreads.append(thread)

    def has_waitfor(self):
        for each_thread in self.waitforthreads:
            if not each_thread.is_stop():
                return True
        return False
