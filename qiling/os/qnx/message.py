#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#
import os
from struct import pack, unpack
from ctypes import c_int32
from binascii import hexlify
from qiling.os.filestruct import ql_file
from qiling.os.mapper import QlFsMappedObject
from qiling.os.qnx.const import IO_FLAG_MASK, PAGESIZE, S_IFMT
from qiling.os.qnx.helpers import get_message_body, QnxConn
from qiling.os.qnx.types import file_access, file_stats, file_types, file_open_flags, file_sharing_modes, io_connect_eflag, io_connect_ioflag, io_connect_subtypes, lseek_whence, mem_ctrl_subtypes, mmap_flags, sysconf_conditions, sysconf_consts, sysconf_names, sysconf_subtypes
from qiling.os.posix.const_mapping import _constant_mapping, mmap_prot_mapping, ql_open_flag_mapping
from qiling.os.posix.syscall import ql_syscall_close, ql_syscall_fstat, ql_syscall_lseek, ql_syscall_mmap, ql_syscall_open, ql_syscall_read, ql_syscall_write

# TODO: move this to qiling.os.qnx.const?
_IO_COMBINE_FLAG = 0x8000

def ql_qnx_msg_io_close(ql, coid, smsg, sparts, rmsg, rparts, *args, **kw):
    fd = ql.os.connections[coid].fd
    ql.os.connections[coid].fd = None
    ql.log.debug(f'msg_io_close(coid = {coid} => fd = {fd})')
    return ql_syscall_close(ql, fd)

# lib/c/support/_connect_ctrl.c::_connect_io()
def ql_qnx_msg_io_connect(ql, coid, smsg, sparts, rmsg, rparts, *args, **kw):
    # first iov_t
    iov_base = ql.unpack32(ql.mem.read(smsg, 4))
    iov_len = ql.unpack32(ql.mem.read(smsg + 4, 4))
    assert iov_len == 40, "io_connect: wrong size for first first iov_t"
    # struct _io_connect in lib/c/public/sys/iomsg.h
    (type, subtype, file_type, reply_max, entry_max, key, handle, ioflag, mode, sflag, access, zero, path_len, eflag, extra_type, extra_len) = unpack("<HHIHHIIIIHHHHBBH", ql.mem.read(iov_base, iov_len))
    # second iov_t
    iov_base = ql.unpack32(ql.mem.read(smsg + 8, 4))
    iov_len = ql.unpack32(ql.mem.read(smsg + 12, 4))
    path = ql.mem.read(iov_base, iov_len).decode("utf-8").rstrip('\x00')
    real_path = ql.os.path.transform_to_real_path(path)
    # check parameters
    assert (type, reply_max, entry_max, key, handle, zero, eflag, extra_type) == (0x100, 0xa18, 0x10, 0, 0, 0, 0, 0), "io_connect message is wrong"
    if not subtype in io_connect_subtypes:
        raise NotImplementedError(f'msg_io_connect subtype {subtype} not implemented')
    if not file_type in file_types:
        raise NotImplementedError(f'msg_io_connect file_type {file_type} not implemented')
    if not sflag in file_sharing_modes:
        raise NotImplementedError(f'msg_io_connect sharing flag {sflag} not implemented')
    if access != 0 and not access in file_access:
        raise NotImplementedError(f'msg_io_connect access {access} not implemented')
    ioflag_lo = ioflag & IO_FLAG_MASK
    ioflag_hi = ioflag & (~IO_FLAG_MASK)
    real_mode = mode & (~S_IFMT)
    # ql.log.debug(f'msg_io_connect(subtype = {subtype}, file_type = {file_type}, ioflag = 0x{ioflag:x}, mode = 0x{mode:x}, sflag = 0x{sflag:x}, access = {access}, extra_len = {extra_len})')
    ql.log.debug(f'msg_io_connect(subtype = {io_connect_subtypes[subtype]}, file_type = {file_types[file_type]}, ioflag = {_constant_mapping(ioflag_lo, io_connect_ioflag) + _constant_mapping(ioflag_hi, file_open_flags)}, mode = 0x{real_mode:x}, type = {_constant_mapping((mode & S_IFMT), file_stats)}, sflag = {file_sharing_modes[sflag]})')
    # convert _IO_FLAG_? to O_? flag and then to O_? flags of host system
    ioflag -= 1
    #ioflag = ql_open_flag_mapping(ql, ioflag)
    # handle subtype
    if subtype == 0: # == _IO_CONNECT_COMBINE
        # third iov_t if required for alignment
        if sparts > 2:
            iov_base = ql.unpack32(ql.mem.read(smsg + 16, 4))
            iov_len = ql.unpack32(ql.mem.read(smsg + 20, 4))
        # forth iov_t
        if sparts > 3:
            iov_base = ql.unpack32(ql.mem.read(smsg + 24, 4))
            iov_len = ql.unpack32(ql.mem.read(smsg + 28, 4))
        # struct _io_* in lib/c/public/sys/iomsg.h
        iov_msg = ql.mem.read(iov_base, iov_len)
        (x_type, x_combine_len) = unpack("<HH", iov_msg[:4])
        # ql.log.debug(f'msg_io_connect(_IO_CONNECT_COMBINE): extra iov_t(type = 0x{x_type:x}, combine_len = 0x{x_combine_len:x})')
        if x_type == 0x104: # == _IO_STAT
            # struct _io_stat in lib/c/public/sys/iomsg.h
            (x_type, x_combine_len, x_zero) = unpack("<HHI", iov_msg)
            ql.log.debug(f'msg_io_connect(_IO_CONNECT_COMBINE + _IO_STAT, path = {path})')
            if not os.path.exists(real_path):
                return -1
            # reply iov_t no. 2
            iov_base = ql.unpack32(ql.mem.read(rmsg + 8, 4))
            iov_len = ql.unpack32(ql.mem.read(rmsg + 12, 4))
            #ql.os.fd[coid] = ql.os.fs_mapper.open_ql_file(path, ioflag, real_mode)
            ql.os.connections[coid].fd = ql_syscall_open(ql, ql.unpack32(ql.mem.read(smsg + 8, 4)), ioflag, real_mode)
            ql_syscall_fstat(ql, ql.os.connections[coid].fd, iov_base)
        else:
            raise NotImplementedError(f'msg_io_connect(_IO_CONNECT_COMBINE) for type 0x{x_type:x} not implemented')
    elif subtype == 2: # == _IO_CONNECT_OPEN
        ql.log.debug(f'open(path = {path}, openflags = 0x{ioflag:x}, openmode = 0x{real_mode:x})')
        ql.os.connections[coid].fd = ql_syscall_open(ql, ql.unpack32(ql.mem.read(smsg + 8, 4)), ioflag, real_mode)
        #ql.os.fd[coid] = ql.os.fs_mapper.open_ql_file(path, ioflag, real_mode)
    elif subtype == 5: # == _IO_CONNECT_MKNOD
        ql.log.debug(f'mkdir(path = {real_path}, mode = 0x{real_mode:x})')
        os.mkdir(real_path, real_mode)
    else:
        raise NotImplementedError(f'msg_io_connect for {io_connect_subtypes[subtype]} not implemented')
    # reply iov_t no. 1
    iov_base = ql.unpack32(ql.mem.read(rmsg, 4))
    iov_len = ql.unpack32(ql.mem.read(rmsg + 4, 4))
    assert iov_len == 20, "msg_io_connect() reply iov_t 1 wrong size"
    if os.path.isdir(real_path):
        eflag = io_connect_eflag['_IO_CONNECT_EFLAG_DIR']
    elif path.endswith('..'):
        eflag = io_connect_eflag['_IO_CONNECT_EFLAG_DOTDOT']
    elif path.endswith('.'):
        eflag = io_connect_eflag['_IO_CONNECT_EFLAG_DOT']
    else:
        eflag = 0
    if os.path.islink(real_path):
        umask = file_stats['_S_IFLNK']
    elif os.path.isdir(real_path):
        umask = file_stats['_S_IFDIR']
    elif os.path.isfile(real_path):
        umask = file_stats['_S_IFREG']
    else:
        ql.log.warn("msg_io_connect(): type of {real_path} not handled properly?")
        umask = 0
    # struct _io_connect_link_reply in lib/c/public/sys/iomsg.h
    ql.mem.write(iov_base, pack("<IIBBHIHH", 0, file_type, eflag, 0, 0, umask, 0, 0))
    return 0

# lib/c/1/lseek.c
def ql_qnx_msg_io_lseek(ql, coid, smsg, sparts, rmsg, rparts, *args, **kw):
    # struct _io_lseek in lib/c/public/sys/iomsg.h
    (type, combine_len, whence, zero, offset) = unpack("<HHhHQ", ql.mem.read(smsg, 16))
    # check parameters
    assert (c_int32(sparts).value, c_int32(rparts).value) == (-16, -8), "input/output sizes are wrong"
    assert (type, combine_len, zero) == (0x109, 16, 0), "io_stat message is wrong"
    if not whence in lseek_whence:
        raise NotImplementedError("unknown lseek direction")
    fd = ql.os.connections[coid].fd
    ql.log.debug(f'msg_io_lseek(coid = {coid} => fd = {fd}, offset = {offset}, whence = {lseek_whence[whence]})')
    # lseek file
    regreturn = ql_syscall_lseek(ql, fd, offset, whence)
    ql.mem.write(rmsg, ql.pack64(regreturn))
    return 0

# lib/c/1/fstat.c
def ql_qnx_msg_io_stat(ql, coid, smsg, sparts, rmsg, rparts, *args, **kw):
    # struct _io_stat in lib/c/public/sys/iomsg.h
    (type, combine_len, zero) = unpack("<HHI", ql.mem.read(smsg, 8))
    # check parameters
    assert (c_int32(sparts).value, c_int32(rparts).value) == (-8, -72), "input/output sizes are wrong"
    assert (type, combine_len, zero) == (0x104, 8, 0), "io_stat message is wrong"
    fd = ql.os.connections[coid].fd
    ql.log.debug(f'msg_io_stat(coid = {coid} => fd = {fd})')
    # fstat file
    return ql_syscall_fstat(ql, fd, rmsg)

def ql_qnx_msg_io_write(ql, coid, smsg, sparts, rmsg, rparts, *args, **kw):
    # struct _io_write in lib/c/public/sys/iomsg.h
    (type, combine_len, nbytes, xtype, zero) = unpack("<HHiII", get_message_body(ql, smsg, sparts))

    if combine_len & _IO_COMBINE_FLAG != 0 or xtype != 0:
        raise NotImplementedError("IO combine and XTYPE support not implemented")

    return ql_syscall_write(ql, ql.os.connections[coid].fd, ql.unpack32(ql.mem.read(smsg + 8, 4)), nbytes)

def ql_qnx_msg_io_read(ql, coid, smsg, sparts, rmsg, rparts, *args, **kw):
    (type_, combine_len, nbytes, xtype, zero) = unpack("<HHIII", get_message_body(ql, smsg, sparts))

    if combine_len & _IO_COMBINE_FLAG != 0 or xtype != 0:
        raise NotImplementedError("IO combine and XTYPE support not implemented")

    rlen = c_int32(rparts).value
    assert nbytes == -rlen, "different sizes for io_read"
    return ql_syscall_read(ql, ql.os.connections[coid].fd, rmsg, nbytes)

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
