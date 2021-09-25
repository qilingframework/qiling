#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os
from multiprocessing import Process

from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS
from qiling.os.posix.const import THREAD_EVENT_CREATE_THREAD

def ql_syscall_clone(ql: Qiling, flags: int, child_stack: int, parent_tidptr: int, newtls: int, child_tidptr: int):
    CSIGNAL              = 0x000000ff
    CLONE_VM             = 0x00000100
    CLONE_FS             = 0x00000200
    CLONE_FILES          = 0x00000400
    CLONE_SIGHAND        = 0x00000800
    CLONE_PIDFD          = 0x00001000
    CLONE_PTRACE         = 0x00002000
    CLONE_VFORK          = 0x00004000
    CLONE_PARENT         = 0x00008000
    CLONE_THREAD         = 0x00010000
    CLONE_NEWNS          = 0x00020000
    CLONE_SYSVSEM        = 0x00040000
    CLONE_SETTLS         = 0x00080000
    CLONE_PARENT_SETTID  = 0x00100000
    CLONE_CHILD_CLEARTID = 0x00200000
    CLONE_DETACHED       = 0x00400000
    CLONE_UNTRACED       = 0x00800000
    CLONE_CHILD_SETTID   = 0x01000000
    CLONE_NEWCGROUP      = 0x02000000
    CLONE_NEWUTS         = 0x04000000
    CLONE_NEWIPC         = 0x08000000
    CLONE_NEWUSER        = 0x10000000
    CLONE_NEWPID         = 0x20000000
    CLONE_NEWNET         = 0x40000000
    CLONE_IO             = 0x80000000

    # X8664 flags, child_stack, parent_tidptr, child_tidptr, newtls
    if ql.archtype== QL_ARCH.X8664:
        ori_newtls = child_tidptr
        child_tidptr = newtls
        newtls = ori_newtls

    f_th = ql.os.thread_management.cur_thread
    set_child_tid_addr = None

    # Shared virtual memory
    if not (flags & CLONE_VM):
        # FIXME: need a proper os.fork() for Windows
        if ql.platform == QL_OS.WINDOWS:
            try:
                pid = Process()
                pid = 0
            except:
                pid = -1
        else:
            pid = os.fork()

        if pid == 0:
            ql.os.child_processes = True

            f_th.update_global_thread_id()
            f_th.new_thread_id()

            if flags & CLONE_SETTLS == CLONE_SETTLS:
                f_th.set_thread_tls(newtls)

            if flags & CLONE_CHILD_CLEARTID == CLONE_CHILD_CLEARTID:
                f_th.set_clear_child_tid_addr(child_tidptr)

            if child_stack != 0:
                ql.arch.set_sp(child_stack)

        # ql.log.debug(f'clone(new_stack = {child_stack:#x}, flags = {flags:#x}, tls = {newtls:#x}, ptidptr = {parent_tidptr:#x}, ctidptr = {child_tidptr:#x}) = {regreturn:d}')
        ql.emu_stop()

        return pid

    if flags & CLONE_CHILD_SETTID == CLONE_CHILD_SETTID:
        set_child_tid_addr = child_tidptr

    th = ql.os.thread_class.spawn(ql, ql.reg.arch_pc + 2, ql.os.exit_point, set_child_tid_addr = set_child_tid_addr)
    th.path = f_th.path
    ql.log.debug(f'{str(th)} created')

    if flags & CLONE_PARENT_SETTID == CLONE_PARENT_SETTID:
        ql.mem.write(parent_tidptr, ql.pack32(th.id))

    ctx = ql.save(reg=True, mem=False)
    # Whether to set a new tls
    if flags & CLONE_SETTLS == CLONE_SETTLS:
        ql.log.debug(f"new_tls={newtls:#x}")
        th.set_thread_tls(newtls)

    if flags & CLONE_CHILD_CLEARTID == CLONE_CHILD_CLEARTID:
        th.set_clear_child_tid_addr(child_tidptr)

    # Set the stack and return value of the new thread
    # (the return value of the child thread is 0, and the return value of the parent thread is the tid of the child thread)
    # and save the current context.
    regreturn = 0
    ql.reg.arch_sp = child_stack

    # We have to find next pc manually for some archs since the pc is current instruction (like `syscall`).
    if ql.archtype in (QL_ARCH.X8664, ):
        ql.reg.arch_pc += list(ql.disassembler.disasm_lite(bytes(ql.mem.read(ql.reg.arch_pc, 4)), ql.reg.arch_pc))[0][1]
        ql.log.debug(f"Fix pc for child thread to {hex(ql.reg.arch_pc)}")

    ql.os.set_syscall_return(0)
    th.save()

    if th is None or f_th is None:
        raise Exception()

    ql.log.debug(f'Currently running pid is: {os.getpid():d}; tid is: {ql.os.thread_management.cur_thread.id:d}')
    # ql.log.debug(f'clone(new_stack = {child_stack:#x}, flags = {flags:#x}, tls = {newtls:#x}, ptidptr = {parent_tidptr:#x}, ctidptr = {child_tidptr:#x}) = {regreturn:d}')

    # Restore the stack and return value of the parent process
    ql.restore(ctx)
    regreturn = th.id

    # Break the parent process and enter the add new thread event
    ql.emu_stop()
    f_th.stop_event = THREAD_EVENT_CREATE_THREAD
    f_th.stop_return_val = th

    ql.log.debug(f'Currently running pid is: {os.getpid():d}; tid is: {ql.os.thread_management.cur_thread.id:d}')
    # ql.log.debug(f'clone(new_stack = {child_stack:#x}, flags = {flags:#x}, tls = {newtls:#x}, ptidptr = {parent_tidptr:#x}, ctidptr = {child_tidptr:#x}) = {regreturn:d}')

    return regreturn

def ql_syscall_sched_yield(ql: Qiling):
    return 0
