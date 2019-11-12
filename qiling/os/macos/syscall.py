#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
#
# LAU kaijern (xwings) <kj@qiling.io>
# NGUYEN Anh Quynh <aquynh@gmail.com>
# DING tianZe (D1iv3) <dddliv3@gmail.com>
# SUN bowen (w1tcher) <w1tcher.bupt@gmail.com>
# CHEN huitao (null) <null@qiling.io>
# YU tong (sp1ke) <spikeinhouse@gmail.com>
import struct
import sys
import os
import string
import resource
import socket
import time
import io
import select
import random

from unicorn import *
from unicorn.arm_const import *
from unicorn.x86_const import *
from unicorn.arm64_const import *
from unicorn.mips_const import *

from qiling.os.utils import *
from qiling.os.macos.define_values import *
from qiling.arch.filetype import *
from qiling.arch.x86 import *

# TODO: We need to finish these syscall
# there are three kinds of syscall, we often use posix syscall, mach syscall is used by handle mach msg
# Unfortunately we dont have enough doc about mach syscall 

################
# mach syscall #
################

# 0x1a
def ql_x86_syscall_mach_reply_port(ql, uc, null0, null1, null2, null3, null4, null5):
    ql.nprint("syscall[mach] >> mach reply port")

# 0x1c
def ql_x86_syscall_task_self_trap(ql, uc, null0, null1, null2, null3, null4, null5):
    ql.nprint("syscall[mach] >> task self trap")

# 0x1d
def ql_x86_syscall_host_self_trap(ql, uc, null0, null1, null2, null3, null4, null5):
    ql.nprint("syscall[mach] >> host_self_trap")

# 0x1f
def ql_x86_syscall_mach_msg_trap(ql, uc, args, null1, null2, null3, null4, null5):
    ql.nprint("syscall[mach] >> mach_msg_trap(0x%X)" % args)
    ql_definesyscall_return(ql, uc, MACH_MSG_SUCCESS)


#################
# POSIX syscall #
#################

# 0x30 
def ql_syscall_sigprocmask(ql, uc, how, mask, omask, null0, null1, null2):
    ql.nprint("syscall >> sigprocmask(how: 0x%X, mask: 0x%X, omask: 0x%X)" % (how, mask, omask))

# 0x174
def ql_syscall_thread_selfid(ql, uc, null0, null1, null2, null3, null4, null5):
    ql.nprint("syscall >> thread selfid")

# 0xa9
def ql_syscall_csops(ql, uc, pid, ops, useraddr, usersize, null0, null1):
    ql.nprint("syscall >> csops(pid: %d, ops: 0x%X, useraddr: 0x%X, usersize: 0x%X)" % (pid, ops, useraddr, usersize))

# 0x1e3
def ql_syscall_csrctl(ql, uc, op, useraddr, usersize, null0, null1, null2):
    ql_definesyscall_return(ql, uc, 1)

# 0x1f4
def ql_syscall_getentropy(ql, uc, buffer, size, null0, null1, null2, null3):
    ql.nprint("syscall >> getentropy(buffer: 0x%X, size: %d)" % (buffer, size))
    ql_definesyscall_return(ql, uc, 0)


# 0x208
def ql_syscall_terminate_with_payload(ql, uc, pid, reason_namespace, reason_code, payload, payload_size, reason_string):
    ql.nprint("syscall >> terminate_with_payload(pid: %d, reason_namespace: 0x%X, reason_code: 0x%X, payload: 0x%X \
            payload_size: 0x%X, reason_string: 0x%X)" % (pid, reason_namespace, reason_code, 
            payload, payload_size, reason_string))
    ql_definesyscall_return(ql, uc, 0)
    uc.emu_stop()

# 0x209
def ql_syscall_abort_with_payload(ql, uc, reason_namespace, reason_code, payload, payload_size, reason_string, reason_flags):
    ql.nprint("syscall >> abort_with_payload(reason_namespace: 0x%X, reason_code: 0x%X, payload: 0x%X, payload_size: 0x%X, reason_string: 0x%X,\
            reason_flags: 0x%X)" % (reason_namespace, reason_code, payload, payload_size, reason_string, reason_flags))
    ql_definesyscall_return(ql, uc, 0)


################
# mdep syscall #
################

# 0x3
def ql_x86_syscall_thread_set_tsd_base(ql, uc, u_info_addr, null0, null1, null2, null3, null4):
    ql.nprint("syscall[mdep] >> thread set tsd base")
    return 
    # ql.nprint("set_thread_area(u_info_addr= 0x%x)" % u_info_addr)
    # u_info = uc.mem_read(u_info_addr, 4 * 3)
    # base = ql.unpack32(u_info[4 : 8])
    # limit = ql.unpack32(u_info[8 : 12])
    # ql.nprint("|-->>> set_thread_area base : 0x%x limit is : 0x%x" % (base, limit))
    # ql_x86_setup_syscall_set_thread_area(ql, uc, base, limit)
    # uc.mem_write(u_info_addr, ql.pack32(12))
    # regreturn = 0
    # ql_definesyscall_return(ql, uc, regreturn)
