#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#
from struct import pack, unpack
from ctypes import c_int32
from binascii import hexlify
from qiling.os.qnx.helpers import get_message_body
from qiling.os.posix.syscall import ql_syscall_read, ql_syscall_write, ql_syscall_mmap

_IO_COMBINE_FLAG = 0x8000


def ql_qnx_msg_io_write(ql, coid, smsg, sparts, rmsg, rparts, *args, **kw):
    (type_, combine_len, nbytes, xtype, zero) = unpack("<HHIII", get_message_body(ql, smsg, sparts))

    if combine_len & _IO_COMBINE_FLAG != 0 or xtype != 0:
        raise NotImplementedError("IO combine and XTYPE support not implemented")

    return ql_syscall_write(ql, coid, ql.unpack32(ql.mem.read(smsg + 8, 4)), nbytes)

def ql_qnx_msg_io_read(ql, coid, smsg, sparts, rmsg, rparts, *args, **kw):
    (type_, combine_len, nbytes, xtype, zero) = unpack("<HHIII", get_message_body(ql, smsg, sparts))

    if combine_len & _IO_COMBINE_FLAG != 0 or xtype != 0:
        raise NotImplementedError("IO combine and XTYPE support not implemented")

    return ql_syscall_read(ql, coid, rmsg, rparts)

def ql_qnx_msg_mem_map(ql, coid, smsg, sparts, rmsg, rparts, *args, **kw):
    (type_, zero, reserved1, addr, len_, prot, flags,
            fd, preload, align, offset) = unpack("<HHIQQIIiIQq", get_message_body(ql, smsg, sparts))

    ret = ql_syscall_mmap(ql, addr, len_, prot, flags, fd, offset)
    if c_int32(sparts).value < 0:
        ql.mem.write(rmsg, pack("<QQQ", len_, ret, ret))
    else:
        raise NotImplementedError("mmap with IOV not implemented")

    return 0

def ql_qnx_msg_sys_conf(ql, coid, smsg, sparts, rmsg, rparts, *args, **kw):
    (type_, subtype_, cmd_, name_, spare, value) = unpack("<HHiiiq", get_message_body(ql, smsg, sparts))

    # services/system/public/sys/sysmsg.h
    if subtype_ == 0:
        subtype = "_SYS_SUB_GET"
    elif subtype_ == 1:
        subtype = "_SYS_SUB_SET"
    else:
        raise NotImplementedError("subtype not implemented")

    # lib/c/public/sys/conf.h
    if cmd_ == (1 << 20):
        # checking for string
        cmd = "_CONF_STR"
    elif cmd_ == (2 << 20):
        # checking for number
        cmd = "_CONF_NUM"
    else:
        raise NotImplementedError("cmd type not implemented")

    # lib/c/public/confname.h
    if name_ == 200:
        # search path for dynamic loader, e.g. /usr/lib
        name = "_CS_LIBPATH"
    elif name_ == 201:
        name = "_CS_DOMAIN"
    elif name_ == 202:
        name = "_CS_RESOLVE"
    elif name_ == 203:
        name = "_CS_TIMEZONE"
    elif name_ == 204:
        name = "_CS_LOCALE"
    else:
        raise NotImplementedError("cmd type not implemented")

    # output syscall with decoded arguments
    ql.log.debug("sys_conf(subtype=%s, cmd=%s, name=%s, spare=%d, value=%d)" % (subtype, cmd, name, spare, value))

    # sys_conf(_SYS_SUB_GET, _CONF_STR, _CS_LIBPATH)
    if subtype_ == 0 and cmd_ == (1 << 20) and name_ == 200:
        libpath = "/usr/lib"
        # first iov_t
        iov_base = ql.unpack32(ql.mem.read(rmsg, 4))
        iov_len = ql.unpack32(ql.mem.read(rmsg + 4, 4))
        ql.mem.write(iov_base, pack("<IIIiq", 0, 0, 0, 0, len(libpath)))
        if value != 0:
            # second iov_t
            iov_base = ql.unpack32(ql.mem.read(rmsg + 8, 4))
            iov_len = ql.unpack32(ql.mem.read(rmsg + 12, 4))
            ql.mem.write(iov_base, pack("<s", libpath.encode("utf-8")))

    return 0

def ql_syscall_connect_attach(ql, nd, pid, chid, index, flags, *args, **kw):
    return 42

def ql_syscall_connect_detach(ql, coid, *args, **kw):
    return 0
