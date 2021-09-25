#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.const import QL_ARCH

def map_msgtype(ql, msgtype):
    if ql.archtype == QL_ARCH.ARM:
        for k, v in msgtype_table.items():
            if v == msgtype:
                return f'ql_qnx_msg_{k}'

# QNX message types extracted from openqnx services/system/public/sys/sysmsg.h
msgtype_table = {
    # services/system/public/sys/sysmsg.h
    "sys_conf":   (0x000),
    "sys_cmd":    (0x001),
    "sys_log":    (0x002),
    "sys_vendor": (0x003),

    # services/system/public/sys/memmsg.h
    "mem_map":        (0x040),
    "mem_ctrl":       (0x041),
    "mem_info":       (0x042),
    "mem_offset":     (0x043),
    "mem_debug_info": (0x044),
    "mem_swap":       (0x045),
    "mem_pmem_add":   (0x046),
    "mem_peer":       (0x047),

    # lib/c/public/sys/iomsg.h
    "io_connect":         (0x100),
    "io_read":            (0x101),
    "io_write":           (0x102),
    "io_rsvd_close_ocb":  (0x103),
    "io_stat":            (0x104),
    "io_notify":          (0x105),
    "io_devctl":          (0x106),
    "io_rsvd_unblock":    (0x107),
    "io_pathconf":        (0x108),
    "io_lseek":           (0x109),
    "io_chmod":           (0x10a),
    "io_chown":           (0x10b),
    "io_utime":           (0x10c),
    "io_openfd":          (0x10d),
    "io_fdinfo":          (0x10e),
    "io_lock":            (0x10f),
    "io_space":           (0x110),
    "io_shutdown":        (0x111),
    "io_mmap":            (0x112),
    "io_msg":             (0x113),
    "io_rsvd":            (0x114),
    "io_dup":             (0x115),
    "io_close":           (0x116),
    "io_rsvd_lock_ocb":   (0x117),
    "io_rsvd_unlock_ocb": (0x118),
    "io_sync":            (0x119),
    "io_power":           (0x11a),
}
