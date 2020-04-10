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

def ql_syscall_set_robust_list(ql, set_robust_list_head_ptr, set_robust_list_head_len, *args, **kw):
    if ql.thread_management == None:
        regreturn = 0
    else:
        ql.thread_management.cur_thread.robust_list_head_ptr = set_robust_list_head_ptr
        ql.thread_management.cur_thread.robust_list_head_len = set_robust_list_head_len
    regreturn = 0
    ql.nprint("set_robust_list(%x, %x) = %d"%(set_robust_list_head_ptr, set_robust_list_head_len, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_futex(ql, futex_uaddr, futex_op, futex_val, futex_timeout, futex_uaddr2, futex_val3):
    FUTEX_WAIT = 0
    FUTEX_WAKE = 1
    FUTEX_FD = 2
    FUTEX_REQUEUE = 3
    FUTEX_CMP_REQUEUE = 4
    FUTEX_WAKE_OP = 5
    FUTEX_LOCK_PI = 6
    FUTEX_UNLOCK_PI = 7
    FUTEX_TRYLOCK_PI = 8
    FUTEX_WAIT_BITSET = 9
    FUTEX_WAKE_BITSET = 10
    FUTEX_WAIT_REQUEUE_PI = 11
    FUTEX_CMP_REQUEUE_PI = 12
    FUTEX_PRIVATE_FLAG = 128

    if futex_op & (FUTEX_PRIVATE_FLAG - 1) == FUTEX_WAIT:
        # def futex_wait_addr(ql, th, arg):
        #     addr, val = arg
        #     if ql.unpack32(ql.mem.read(addr, 4)) != val:
        #         return False
        #     else:
        #         return True
        if ql.unpack32(ql.mem.read(futex_uaddr, 4)) == futex_val:
            ql.uc.emu_stop()
            regreturn = 0
            ql.os.futexm.futex_wait(futex_uaddr, ql.thread_management.cur_thread)
        else:
            regreturn = -1
        ql.nprint("futex(%x, %d, %d, %x) = %d" % (futex_uaddr, futex_op, futex_val, futex_timeout, regreturn))
    elif futex_op & (FUTEX_PRIVATE_FLAG - 1) == FUTEX_WAKE:
        regreturn = 0
        ql.os.futexm.futex_wake(futex_uaddr, futex_val)
        ql.nprint("futex(%x, %d, %d) = %d" % (futex_uaddr, futex_op, futex_val, regreturn))
    else:
        ql.nprint("futex(%x, %d, %d) = ?" % (futex_uaddr, futex_op, futex_val))
        ql.uc.emu_stop()
        ql.thread_management.cur_thread.stop()
        ql.thread_management.cur_thread.stop_event = THREAD_EVENT_EXIT_GROUP_EVENT
        regreturn = 0

    ql_definesyscall_return(ql, regreturn)
