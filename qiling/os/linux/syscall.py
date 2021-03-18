#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.arch.x86_const import *
from qiling.const import QL_ARCH

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
