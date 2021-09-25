#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.arch.x86_const import FSMSR, GSMSR

def ql_syscall_arch_prctl(ql: Qiling, code: int, addr: int):
    ARCH_SET_GS = 0x1001
    ARCH_SET_FS = 0x1002
    ARCH_GET_FS = 0x1003
    ARCH_GET_GS = 0x1004

    handlers = {
        ARCH_SET_GS : lambda : ql.reg.msr(GSMSR, addr),
        ARCH_SET_FS : lambda : ql.reg.msr(FSMSR, addr),
        ARCH_GET_FS : lambda : ql.mem.write(addr, ql.pack64(ql.reg.msr(FSMSR))),
        ARCH_GET_GS : lambda : ql.mem.write(addr, ql.pack64(ql.reg.msr(GSMSR)))
    }

    if code not in handlers:
        raise NotImplementedError(f'prctl code {code:#x} not implemented')

    handlers[code]()

    return 0

def ql_syscall_prctl(ql: Qiling, option: int, arg2: int, arg3: int, arg4: int, arg5: int):
    return 0
