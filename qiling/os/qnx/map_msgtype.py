#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.const import QL_ARCH


def map_msgtype(ql, msgtype):
    if ql.archtype == QL_ARCH.ARM:
        for k, v in msgtype_table.items():
            if v == msgtype:
                return f"ql_qnx_msg_{k}"


# QNX message types extracted from openqnx
msgtype_table = {
    "mem_map": (0x040),
    # lib/c/public/sys/iomsg.h
    "io_connect": (0x100),
    "io_read": (0x101),
    "io_write": (0x102),
    "io_devctl": (0x106),
}
