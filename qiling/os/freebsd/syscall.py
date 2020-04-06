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
from qiling.arch.utils import *
from qiling.const import *


def ql_syscall_clock_gettime(ql, clock_gettime_clock_id, clock_gettime_timespec, *args, **kw):
    ql.nprint("clock_gettime()")
    regreturn = 0
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_sysarch(ql, op, parms, *args, **kw):
    """
    wild guess, of cause not working
    """
    
    regreturn = 0
    ql.GS_SEGMENT_ADDR = 0x6000
    ql.GS_SEGMENT_SIZE = 0x8000
    GSMSR = 0xC0000101
    FSMSR = 0xC0000100

    #ql.mem.map(ql.GS_SEGMENT_ADDR, ql.GS_SEGMENT_SIZE)
    #ql.uc.msr_write(GSMSR, ql.GS_SEGMENT_ADDR)
    ql.uc.msr_write(FSMSR, parms)

    #op_buf = ql.pack32(op)
    #ql.mem.write(parms, op_buf)
    ql.nprint("sysarch(0x%x,0x%x) = %i" % (op, parms, regreturn))
    ql_definesyscall_return(ql, regreturn)