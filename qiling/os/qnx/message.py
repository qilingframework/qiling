#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#
from struct import pack, unpack
from ctypes import c_int32
from binascii import hexlify
from qiling.os.mapper import QlFsMappedObject
from qiling.os.qnx.helpers import get_message_body
from qiling.os.posix.syscall import ql_syscall_read, ql_syscall_write, ql_syscall_mmap

_IO_COMBINE_FLAG = 0x8000

def ql_qnx_msg_io_close(ql, coid, smsg, sparts, rmsg, rparts, *args, **kw):
    ql.log.debug("io_close(fd = %d)" % coid)
    ql.os.fd[coid].close()
    ql.os.fd[coid] = 0

# lib/c/support/_connect_ctrl.c::_connect_io()
def ql_qnx_msg_io_connect(ql, coid, smsg, sparts, rmsg, rparts, *args, **kw):
    # first iov_t
    iov_base = ql.unpack32(ql.mem.read(smsg, 4))
    iov_len = ql.unpack32(ql.mem.read(smsg + 4, 4))
    assert iov_len == 40, "io_connect: wrong size for first first iov_t"
    # lib/c/public/sys/iomsg.h
    (type_, subtype_, file_type_, reply_max_, entry_max_, key_, handle_, ioflag_, mode_, sflag_, access_, zero_, path_len_, eflag_, extra_type_, extra_len_) = unpack("<HHIHHIIIIHHHHBBH", ql.mem.read(iov_base, iov_len))
    ql.log.debug("io_connect(type = %d, subtype = %d, file_type = %d, replay_max = %d, entry_max = %d, key = %d, handle = %d, ioflag = %d, mode = %d, sflag = %d, access = %d, zero = %d, path_len = %d, eflag = %d, extra_type = %d, extra_len = %d)" % (type_, subtype_, file_type_, reply_max_, entry_max_, key_, handle_, ioflag_, mode_, sflag_, access_, zero_, path_len_, eflag_, extra_type_, extra_len_))
    # second iov_t
    iov_base = ql.unpack32(ql.mem.read(smsg + 8, 4))
    iov_len = ql.unpack32(ql.mem.read(smsg + 12, 4))
    path = ql.mem.read(iov_base, iov_len).decode("utf-8").rstrip('\x00')
    # ignore third iov_t
    if mode_ == 0:
        mode = "O_RDONLY"
    elif mode_ == 1:
        mode = "O_WRONLY"
    elif mode_ == 2:
        mode = "O_RDWR"
    else:
        raise NotImplementedError("file mode not implemented")
    ql.log.debug("io_connect(fd = %d, path = %s, mode = %s)" % (coid, path, mode))
    # connect file to fd
    ql.os.fd[coid] = ql.os.fs_mapper.open_ql_file(path, mode_, ioflag_)
    return 0

# lib/c/1/fstat.c
def ql_qnx_msg_io_stat(ql, coid, smsg, sparts, rmsg, rparts, *args, **kw):
    ql.log.debug("io_stat(fd = %d)" % coid)
    # struct _io_stat in lib/c/public/sys/iomsg.h
    (type_, combine_len_, zero_) = unpack("<HHI", ql.mem.read(smsg, 8))
    # check parameters
    assert (type_, combine_len_, zero_) == (0x104, 8, 0), "io_stat message is wrong"
    assert (c_int32(sparts).value, c_int32(rparts).value) == (-8, -72), "input/output sizes are wrong"
    # struct stat in lib/c/public/sys/stat.h
    stat = ql.os.fd[coid].fstat()
    ql.mem.write(rmsg, pack("<QQIIiiIIIIIIiIQ", stat.st_ino, stat.st_size, stat.st_dev, stat.st_rdev, stat.st_uid, stat.st_gid, int(stat.st_mtime), int(stat.st_atime), int(stat.st_ctime), stat.st_mode, stat.st_nlink, stat.st_blksize, stat.st_blocks, stat.st_blksize, stat.st_blocks))
    return 0

def ql_qnx_msg_io_write(ql, coid, smsg, sparts, rmsg, rparts, *args, **kw):
    (type_, combine_len, nbytes, xtype, zero) = unpack("<HHIII", get_message_body(ql, smsg, sparts))

    if combine_len & _IO_COMBINE_FLAG != 0 or xtype != 0:
        raise NotImplementedError("IO combine and XTYPE support not implemented")

    return ql_syscall_write(ql, coid, ql.unpack32(ql.mem.read(smsg + 8, 4)), nbytes)

def ql_qnx_msg_io_read(ql, coid, smsg, sparts, rmsg, rparts, *args, **kw):
    (type_, combine_len, nbytes, xtype, zero) = unpack("<HHIII", get_message_body(ql, smsg, sparts))

    if combine_len & _IO_COMBINE_FLAG != 0 or xtype != 0:
        raise NotImplementedError("IO combine and XTYPE support not implemented")

    ql.log.debug("io_read(fd = %d, nbytes = %d)" % (coid, nbytes))
    rlen = c_int32(rparts).value
    assert nbytes == -rlen, "different sizes for io_read"
    return ql_syscall_read(ql, coid, rmsg, nbytes)

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
        raise NotImplementedError("name type not implemented")

    # output syscall with decoded arguments
    ql.log.debug("sys_conf(subtype = %s, cmd = %s, name = %s, spare = %d, value = %d)" % (subtype, cmd, name, spare, value))

    # sys_conf(_SYS_SUB_GET, _CONF_STR, _CS_LIBPATH)
    if subtype_ == 0 and cmd_ == (1 << 20) and name_ == 200:
        libpath = "/usr/lib\0"
        # first iov_t
        iov_base = ql.unpack32(ql.mem.read(rmsg, 4))
        iov_len = ql.unpack32(ql.mem.read(rmsg + 4, 4))
        ql.mem.write(iov_base, pack("<IIIiq", 0, 0, 0, 0, len(libpath)))
        if value != 0:
            # second iov_t
            iov_base = ql.unpack32(ql.mem.read(rmsg + 8, 4))
            iov_len = ql.unpack32(ql.mem.read(rmsg + 12, 4))
            ql.mem.write(iov_base, libpath.encode("utf-8"))
    else:
        raise NotImplementedError("sys_conf message type not implemented")

    return 0

def ql_syscall_connect_attach(ql, nd, pid, chid, index, flags, *args, **kw):
    for i in range(256):
        if ql.os.fd[i] == 0:
            idx = i
            break
    ql.os.fd[idx] = QlFsMappedObject()
    return idx

def ql_syscall_connect_detach(ql, coid, *args, **kw):
    ql.log.debug("connect_detach(fd = %d)" % coid)
    if ql.os.fd[coid] != 0 and isinstance(ql.os.fd[coid], ql_file):
        ql.os.fd[coid].close()
    ql.os.fd[coid] = 0
    return 0
