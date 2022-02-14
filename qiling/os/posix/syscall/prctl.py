#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.arch.x86_const import IA32_FS_BASE_MSR, IA32_GS_BASE_MSR

def ql_syscall_arch_prctl(ql: Qiling, code: int, addr: int):
    ARCH_SET_GS = 0x1001
    ARCH_SET_FS = 0x1002
    ARCH_GET_FS = 0x1003
    ARCH_GET_GS = 0x1004

    handlers = {
        ARCH_SET_GS : lambda : ql.arch.msr.write(IA32_GS_BASE_MSR, addr),
        ARCH_SET_FS : lambda : ql.arch.msr.write(IA32_FS_BASE_MSR, addr),
        ARCH_GET_FS : lambda : ql.mem.write_ptr(addr, ql.arch.msr.read(IA32_FS_BASE_MSR), 8),
        ARCH_GET_GS : lambda : ql.mem.write_ptr(addr, ql.arch.msr.read(IA32_GS_BASE_MSR), 8)
    }

    if code not in handlers:
        ql.log.warning(f'prctl code {code:#x} not implemented')
    else:
        handlers[code]()

    return 0

def ql_syscall_prctl(ql: Qiling, option: int, arg2: int, arg3: int, arg4: int, arg5: int):
    return 0
