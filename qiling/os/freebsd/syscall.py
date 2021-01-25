#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


from qiling.arch.x86_const import *

def ql_syscall_clock_gettime(ql, clock_gettime_clock_id, clock_gettime_timespec, *args, **kw):
    ql.log.info("clock_gettime()")
    return 0


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
    ql.log.info("sysarch(0x%x,0x%x) = %i" % (op, parms, regreturn))
    return regreturn
