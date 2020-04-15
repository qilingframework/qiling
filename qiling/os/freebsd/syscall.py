#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from qiling.arch.x86_const import *

def ql_syscall_clock_gettime(ql, clock_gettime_clock_id, clock_gettime_timespec, *args, **kw):
    ql.nprint("clock_gettime()")
    regreturn = 0
    ql.os.definesyscall_return(regreturn)


def ql_syscall_sysarch(ql, op, parms, *args, **kw):
    """
    wild guess, of cause not working
    """
    
    regreturn = 0
    ql.GS_SEGMENT_ADDR = 0x6000
    ql.GS_SEGMENT_SIZE = 0x8000


    #ql.mem.map(ql.GS_SEGMENT_ADDR, ql.GS_SEGMENT_SIZE)
    #ql.reg.msr(GSMSR, ql.GS_SEGMENT_ADDR)
    ql.reg.msr(FSMSR, parms)

    #op_buf = ql.pack32(op)
    #ql.mem.write(parms, op_buf)
    ql.nprint("sysarch(0x%x,0x%x) = %i" % (op, parms, regreturn))
    ql.os.definesyscall_return(regreturn)