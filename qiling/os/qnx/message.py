#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#
from struct import pack, unpack
from ctypes import c_int32
from binascii import hexlify
from qiling.os.qnx.helpers import get_message_body
from qiling.os.posix.syscall import ql_syscall_write, ql_syscall_mmap

_IO_COMBINE_FLAG = 0x8000


def ql_qnx_msg_io_write(ql, coid, smsg, sparts, rmsg, rparts, *args, **kw):
    (type_, combine_len, nbytes, xtype, zero) = unpack("<HHIII", get_message_body(ql, smsg, sparts))

    if combine_len & _IO_COMBINE_FLAG != 0 or xtype != 0:
        raise NotImplementedError("IO combine and XTYPE support not implemented")

    return ql_syscall_write(ql, coid, ql.unpack32(ql.mem.read(smsg + 8, 4)), nbytes)

def ql_qnx_msg_mem_map(ql, coid, smsg, sparts, rmsg, rparts, *args, **kw):
    (type_, zero, reserved1, addr, len_, prot, flags,
            fd, preload, align, offset) = unpack("<HHIQQIIiIQq", get_message_body(ql, smsg, sparts))

    ret = ql_syscall_mmap(ql, addr, len_, prot, flags, fd, offset)
    if c_int32(sparts).value < 0:
        ql.mem.write(rmsg, pack("<QQQ", len_, ret, ret))
    else:
        raise NotImplementedError("mmap with IOV not implemented")

    return 0
