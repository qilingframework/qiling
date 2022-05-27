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

def __get_timespec_struct(archbits: int):
    long  = getattr(ctypes, f'c_int{archbits}')
    ulong = getattr(ctypes, f'c_uint{archbits}')

    class timespec(ctypes.Structure):
        _pack_ = archbits // 8

        _fields_ = (
            ('tv_sec', ulong),
            ('tv_nsec', long)
        )

    return timespec

def __get_timespec_obj(archbits: int):
    now = datetime.now().timestamp()

    tv_sec = floor(now)
    tv_nsec = floor((now - floor(now)) * 1e6)
    ts_cls = __get_timespec_struct(archbits)

    return ts_cls(tv_sec=tv_sec, tv_nsec=tv_nsec)


def ql_syscall_set_thread_area(ql: Qiling, u_info_addr: int):
    if ql.arch.type == QL_ARCH.X86:
        u_info = ql.mem.read(u_info_addr, 4 * 4)
        index = ql.unpack32s(u_info[0 : 4])
        base = ql.unpack32(u_info[4 : 8])
        limit = ql.unpack32(u_info[8 : 12])

        ql.log.debug("set_thread_area base : 0x%x limit is : 0x%x" % (base, limit))

        if index == -1:
            index = ql.os.gdtm.get_free_idx(12)

        if index in (12, 13, 14):
            access = QL_X86_A_PRESENT | QL_X86_A_DATA | QL_X86_A_DATA_WRITABLE | QL_X86_A_PRIV_3 | QL_X86_A_DIR_CON_BIT

            ql.os.gdtm.register_gdt_segment(index, base, limit, access)
            ql.mem.write_ptr(u_info_addr, index, 4)
        else:
            ql.log.warning(f"Wrong index {index} from address {hex(u_info_addr)}")
            return -1

    elif ql.arch.type == QL_ARCH.MIPS:
        CONFIG3_ULR = (1 << 13)
        ql.arch.regs.cp0_config3 = CONFIG3_ULR
        ql.arch.regs.cp0_userlocal = u_info_addr
        ql.arch.regs.v0 = 0
        ql.arch.regs.a3 = 0
        ql.log.debug ("set_thread_area(0x%x)" % u_info_addr)

    return 0


def ql_syscall_set_tls(ql: Qiling, address: int):
    if ql.arch.type == QL_ARCH.ARM:
        ql.arch.regs.c13_c0_3 = address
        ql.mem.write_ptr(ql.arch.arm_get_tls_addr + 16, address, 4)
        ql.arch.regs.r0 = address
        ql.log.debug("settls(0x%x)" % address)

def ql_syscall_clock_gettime(ql: Qiling, clock_id: int, tp: int):
    ts_obj = __get_timespec_obj(ql.arch.bits)
    ql.mem.write(tp, bytes(ts_obj))

    return 0

def ql_syscall_gettimeofday(ql: Qiling, tv: int, tz: int):
    if tv:
        ts_obj = __get_timespec_obj(ql.arch.bits)
        ql.mem.write(tv, bytes(ts_obj))

    if tz:
        ql.mem.write(tz, b'\x00' * 8)

    return 0
