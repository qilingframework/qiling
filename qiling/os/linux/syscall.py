#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.arch.x86_const import *
from qiling.const import QL_ARCH

from datetime import datetime
from math import floor
import ctypes

class timespec(ctypes.Structure):
    _fields_ = [
        ("tv_sec", ctypes.c_uint64),
        ("tv_nsec", ctypes.c_int64)
    ]

    _pack_ = 8


# Temporary dirty fix.
# TODO: Pack ctypes.Structure according to ql.archtype and ql.ostype?
class timespec32(ctypes.Structure):
    _fields_ = [
        ("tv_sec", ctypes.c_uint32),
        ("tv_nsec", ctypes.c_int32)
    ]

    _pack_ = 4

def ql_syscall_set_thread_area(ql: Qiling, u_info_addr, *args, **kw):
    if ql.archtype == QL_ARCH.X86:
        GDT_ENTRY_TLS_MIN = 12
        GDT_ENTRY_TLS_MAX = 14

        u_info = ql.mem.read(u_info_addr, 4 * 4)
        index = ql.unpack32s(u_info[0 : 4])
        base = ql.unpack32(u_info[4 : 8])
        limit = ql.unpack32(u_info[8 : 12])

        ql.log.debug("set_thread_area base : 0x%x limit is : 0x%x" % (base, limit))

        if index == -1:
            index = ql.os.gdtm.get_free_idx(12)

        if index == -1 or index < GDT_ENTRY_TLS_MIN or index > GDT_ENTRY_TLS_MAX:
            ql.log.warning(f"Wrong index {index} from address {hex(u_info_addr)}")
            return -1
        else:
            ql.os.gdtm.register_gdt_segment(index, base, limit, QL_X86_A_PRESENT | QL_X86_A_DATA | QL_X86_A_DATA_WRITABLE | QL_X86_A_PRIV_3 | QL_X86_A_DIR_CON_BIT, QL_X86_S_GDT | QL_X86_S_PRIV_3)
            ql.mem.write(u_info_addr, ql.pack32(index))
            return 0

    elif ql.archtype == QL_ARCH.MIPS:
        CONFIG3_ULR = (1 << 13)
        ql.reg.cp0_config3 = CONFIG3_ULR
        ql.reg.cp0_userlocal = u_info_addr
        ql.reg.v0 = 0
        ql.reg.a3 = 0
        ql.log.debug ("set_thread_area(0x%x)" % u_info_addr)

    return 0


def ql_syscall_set_tls(ql, address, *args, **kw):
    if ql.archtype == QL_ARCH.ARM:
        ql.reg.c13_c0_3 = address
        ql.mem.write(ql.arch.arm_get_tls_addr + 12, ql.pack32(address))
        ql.reg.r0 = address
        ql.log.debug("settls(0x%x)" % address)

def ql_syscall_clock_gettime(ql, clock_gettime_clock_id, clock_gettime_timespec, *args, **kw):    
    now = datetime.now().timestamp()
    tv_sec = floor(now)
    tv_nsec = floor((now - floor(now)) * 1e6)
    if ql.archtype == QL_ARCH.X8664:
        tp = timespec(tv_sec= tv_sec, tv_nsec=tv_nsec)
    else:
        tp = timespec32(tv_sec= tv_sec, tv_nsec=tv_nsec)
    ql.mem.write(clock_gettime_timespec, bytes(tp))

    ql.log.debug("clock_gettime(clock_id = %d, timespec = 0x%x)" % (clock_gettime_clock_id, clock_gettime_timespec))
    
    return 0

def ql_syscall_gettimeofday(ql, gettimeofday_tv, gettimeofday_tz, *args, **kw):
    now = datetime.now().timestamp()
    tv_sec = floor(now)
    tv_nsec = floor((now - floor(now)) * 1e6)
    if ql.archtype == QL_ARCH.X8664:
        tp = timespec(tv_sec= tv_sec, tv_nsec=tv_nsec)
    else:
        tp = timespec32(tv_sec= tv_sec, tv_nsec=tv_nsec)

    if gettimeofday_tv != 0:
        ql.mem.write(gettimeofday_tv, bytes(tp))
    if gettimeofday_tz != 0:
        ql.mem.write(gettimeofday_tz, b'\x00' * 8)
    regreturn = 0
    return regreturn
