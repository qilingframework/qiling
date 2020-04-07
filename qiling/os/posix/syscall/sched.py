#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)
import struct
import sys
import os
import stat
import string
import resource
import socket
import time
import io
import select
import pathlib
import logging
import itertools

# Remove import fcntl due to Windows Limitation
#import fcntl

from unicorn import *
from unicorn.arm_const import *
from unicorn.x86_const import *
from unicorn.arm64_const import *
from unicorn.mips_const import *

# impport read_string and other commom utils.
from qiling.os.utils import *
from qiling.const import *
from qiling.os.linux.thread import *
from qiling.const import *
from qiling.os.posix.filestruct import *
from qiling.os.posix.const_mapping import *
from qiling.utils import *

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

    f_th = ql.thread_management.cur_thread	
    newtls = None
    set_child_tid_addr = None

    # Shared virtual memory
    if clone_flags & CLONE_VM != CLONE_VM:
        pid = os.fork()
        if pid != 0:
            regreturn = pid
            ql.nprint("clone(new_stack = %x, flags = %x, tls = %x, ptidptr = %x, ctidptr = %x) = %d" % (clone_child_stack, clone_flags, clone_newtls, clone_parent_tidptr, clone_child_tidptr, regreturn))
            ql_definesyscall_return(ql, regreturn)
        else:
            ql.child_processes = True

            f_th.update_global_thread_id()
            f_th.new_thread_id()
            f_th.set_thread_log_file(ql.log_dir)

            if clone_flags & CLONE_SETTLS == CLONE_SETTLS:
                if ql.archtype== QL_X86:
                    newtls = ql.mem.read(clone_newtls, 4 * 3)
                else:
                    newtls = clone_newtls
                f_th.set_special_settings_arg(newtls)

            if clone_flags & CLONE_CHILD_CLEARTID == CLONE_CHILD_CLEARTID:
                f_th.set_clear_child_tid_addr(clone_child_tidptr)

            if clone_child_stack != 0:
                ql.arch.set_sp(clone_child_stack)
            regreturn = 0
            ql.nprint("clone(new_stack = %x, flags = %x, tls = %x, ptidptr = %x, ctidptr = %x) = %d" % (clone_child_stack, clone_flags, clone_newtls, clone_parent_tidptr, clone_child_tidptr, regreturn))
            ql_definesyscall_return(ql, regreturn)
        ql.uc.emu_stop()
        return

    if clone_flags & CLONE_PARENT_SETTID == CLONE_PARENT_SETTID:
        set_child_tid_addr = clone_parent_tidptr

    th = Thread(ql, ql.thread_management, total_time = f_th.remaining_time(), set_child_tid_addr = set_child_tid_addr)
    th.set_current_path(f_th.get_current_path())

    # Whether to set a new tls
    if clone_flags & CLONE_SETTLS == CLONE_SETTLS:
        th.set_special_settings_fuc(f_th.special_settings_fuc)
        if ql.archtype== QL_X86:
            newtls = ql.mem.read(clone_newtls, 4 * 3)
        else:
            newtls = clone_newtls
        th.set_special_settings_arg(newtls)

    if clone_flags & CLONE_CHILD_CLEARTID == CLONE_CHILD_CLEARTID:
        th.set_clear_child_tid_addr(clone_child_tidptr)

    # Set the stack and return value of the new thread
    # (the return value of the child thread is 0, and the return value of the parent thread is the tid of the child thread)
    # and save the current context.
    f_sp = ql.arch.get_sp()

    regreturn = 0
    ql_definesyscall_return(ql, regreturn)
    ql.arch.set_sp(clone_child_stack)
    th.save()

    ql.thread_management.cur_thread = th
    ql.dprint(0, "[+] Currently running pid is: %d; tid is: %d " % (
    os.getpid(), ql.thread_management.cur_thread.get_thread_id()))
    ql.nprint("clone(new_stack = %x, flags = %x, tls = %x, ptidptr = %x, ctidptr = %x) = %d" % (
    clone_child_stack, clone_flags, clone_newtls, clone_parent_tidptr, clone_child_tidptr, regreturn))

    # Restore the stack and return value of the parent process
    ql.arch.set_sp(f_sp)
    regreturn = th.get_thread_id()
    ql_definesyscall_return(ql, regreturn)

    # Break the parent process and enter the add new thread event
    ql.uc.emu_stop()
    f_th.stop_event = THREAD_EVENT_CREATE_THREAD
    f_th.stop_return_val = th

    ql.thread_management.cur_thread = f_th
    ql.dprint(0, "[+] Currently running pid is: %d; tid is: %d " % (
    os.getpid(), ql.thread_management.cur_thread.get_thread_id()))
    ql.nprint("clone(new_stack = %x, flags = %x, tls = %x, ptidptr = %x, ctidptr = %x) = %d" % (
    clone_child_stack, clone_flags, clone_newtls, clone_parent_tidptr, clone_child_tidptr, regreturn))
