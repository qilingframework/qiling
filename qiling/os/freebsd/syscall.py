#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
import struct
import sys
import os
import string
import resource
import socket
import time
import io
import select

from unicorn import *
from unicorn.arm_const import *
from unicorn.x86_const import *
from unicorn.arm64_const import *
from unicorn.mips_const import *

# impport read_string and other commom utils.
from qiling.os.utils import *
from qiling.arch.filetype import *


def ql_syscall_clock_gettime(ql, clock_gettime_clock_id, clock_gettime_timespec, null2, null3, null4, null5):
    ql.nprint("clock_gettime()")
    regreturn = 0
    ql_definesyscall_return(ql, regreturn)

def ql_syscall___sysctl(ql, sysctl_name, sysctl_namelen, sysctl_bytes_oldlenp, sysctl_size_oldlenp, sysctl_bytes_newlen, sysctl_size_newlen):
    #path = (ql_read_string(ql, sysctl_namelen))

    # sysctl (name=0x7fffffffe3d8, namelen=2, oldp=0x7fffffffe3d4, oldlenp=0x7fffffffe3e0, newp=0x0, newlen=<optimized out>)
    regreturn = 1
    ql.nprint("__sysctl(0x%x) = %i" % (sysctl_name, regreturn)) 
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_sysarch(ql, op, parms, null2, null3, null4, null5):
    regreturn = 0
    op_buf = ql.pack32(op)
    ql.uc.mem_write(parms, op_buf)
    ql.nprint("sysarch(%i,0x%x) = %i" % (op,parms,regreturn))
    ql_definesyscall_return(ql, regreturn)