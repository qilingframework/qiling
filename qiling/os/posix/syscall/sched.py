#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

from qiling.const import *
from qiling.os.linux.thread import *
from qiling.const import *
from qiling.os.posix.filestruct import *
from qiling.os.filestruct import *
from qiling.os.posix.const_mapping import *
from qiling.exception import *

def ql_syscall_clone(ql, clone_flags, clone_child_stack, clone_parent_tidptr, clone_newtls, clone_child_tidptr, *args, **kw):
    CSIGNAL = 0x000000ff	
    CLONE_VM = 0x00000100	
    CLONE_FS = 0x00000200	
    CLONE_FILES = 0x00000400	
    CLONE_SIGHAND = 0x00000800	
    CLONE_PIDFD = 0x00001000	
    CLONE_PTRACE = 0x00002000	
    CLONE_VFORK = 0x00004000	
    CLONE_PARENT = 0x00008000	
    CLONE_THREAD = 0x00010000	
    CLONE_NEWNS = 0x00020000	
    CLONE_SYSVSEM = 0x00040000	
    CLONE_SETTLS = 0x00080000	
    CLONE_PARENT_SETTID = 0x00100000	
    CLONE_CHILD_CLEARTID = 0x00200000	
    CLONE_DETACHED = 0x00400000	
    CLONE_UNTRACED = 0x00800000	
    CLONE_CHILD_SETTID = 0x01000000	
    CLONE_NEWCGROUP = 0x02000000	
    CLONE_NEWUTS = 0x04000000	
    CLONE_NEWIPC = 0x08000000	
    CLONE_NEWUSER = 0x10000000	
    CLONE_NEWPID = 0x20000000	
    CLONE_NEWNET = 0x40000000	
    CLONE_IO = 0x80000000

    if ql.archtype== QL_ARCH.MIPS32:
        clone_child_tidptr = ql.unpack32(ql.mem.read(clone_child_tidptr, 4))


    f_th = ql.os.thread_management.cur_thread	
    newtls = None
    set_child_tid_addr = None

    # Shared virtual memory
    if clone_flags & CLONE_VM != CLONE_VM:
        pid = os.fork()
        if pid != 0:
            regreturn = pid
            ql.nprint("clone(new_stack = %x, flags = %x, tls = %x, ptidptr = %x, ctidptr = %x) = %d" % (clone_child_stack, clone_flags, clone_newtls, clone_parent_tidptr, clone_child_tidptr, regreturn))
            ql.os.definesyscall_return(regreturn)
        else:
            ql.os.child_processes = True

            f_th.update_global_thread_id()
            f_th.new_thread_id()
            f_th.set_thread_log_file(ql.log_dir)

            if clone_flags & CLONE_SETTLS == CLONE_SETTLS:
                f_th.clone_thread_tls(clone_newtls)

            if clone_flags & CLONE_CHILD_CLEARTID == CLONE_CHILD_CLEARTID:
                f_th.set_clear_child_tid_addr(clone_child_tidptr)

            if clone_child_stack != 0:
                ql.arch.set_sp(clone_child_stack)
            regreturn = 0
            ql.nprint("clone(new_stack = %x, flags = %x, tls = %x, ptidptr = %x, ctidptr = %x) = %d" % (clone_child_stack, clone_flags, clone_newtls, clone_parent_tidptr, clone_child_tidptr, regreturn))
            ql.os.definesyscall_return(regreturn)
        ql.emu_stop()
        return

    if clone_flags & CLONE_CHILD_SETTID == CLONE_CHILD_SETTID:
        set_child_tid_addr = clone_child_tidptr

    th = ql.os.thread_class(ql, ql.os.thread_management, total_time = f_th.remaining_time(), set_child_tid_addr = set_child_tid_addr)
    th.set_current_path(f_th.get_current_path())

    if clone_flags & CLONE_PARENT_SETTID == CLONE_PARENT_SETTID:
        ql.mem.write(clone_parent_tidptr, ql.pack32(th.get_thread_id()))

    # Whether to set a new tls
    if clone_flags & CLONE_SETTLS == CLONE_SETTLS:
        th.clone_thread_tls(clone_newtls)

    if clone_flags & CLONE_CHILD_CLEARTID == CLONE_CHILD_CLEARTID:
        th.set_clear_child_tid_addr(clone_child_tidptr)

    # Set the stack and return value of the new thread
    # (the return value of the child thread is 0, and the return value of the parent thread is the tid of the child thread)
    # and save the current context.
    f_sp = ql.arch.get_sp()

    regreturn = 0
    ql.os.definesyscall_return(regreturn)
    ql.arch.set_sp(clone_child_stack)
    th.store_regs()

    ql.os.thread_management.cur_thread = th
    ql.dprint(D_INFO, "[+] Currently running pid is: %d; tid is: %d " % (
    os.getpid(), ql.os.thread_management.cur_thread.get_thread_id()))
    ql.nprint("clone(new_stack = %x, flags = %x, tls = %x, ptidptr = %x, ctidptr = %x) = %d" % (
    clone_child_stack, clone_flags, clone_newtls, clone_parent_tidptr, clone_child_tidptr, regreturn))

    # Restore the stack and return value of the parent process
    ql.arch.set_sp(f_sp)
    regreturn = th.get_thread_id()
    ql.os.definesyscall_return(regreturn)

    # Break the parent process and enter the add new thread event
    ql.emu_stop()
    f_th.stop_event = THREAD_EVENT_CREATE_THREAD
    f_th.stop_return_val = th

    ql.os.thread_management.cur_thread = f_th
    ql.dprint(D_INFO, "[+] Currently running pid is: %d; tid is: %d " % (
    os.getpid(), ql.os.thread_management.cur_thread.get_thread_id()))
    ql.nprint("clone(new_stack = %x, flags = %x, tls = %x, ptidptr = %x, ctidptr = %x) = %d" % (
    clone_child_stack, clone_flags, clone_newtls, clone_parent_tidptr, clone_child_tidptr, regreturn))
