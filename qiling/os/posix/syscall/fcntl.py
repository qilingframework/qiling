#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os
from pathlib import Path

from qiling import Qiling
from qiling.const import QL_OS, QL_ARCH
from qiling.exception import QlSyscallError
from qiling.os.posix.const import *
from qiling.os.posix.const_mapping import ql_open_flag_mapping
from qiling.os.posix.filestruct import ql_socket

def ql_syscall_open(ql: Qiling, filename: int, flags: int, mode: int):
    path = ql.os.utils.read_cstring(filename)
    real_path = ql.os.path.transform_to_real_path(path)
    relative_path = ql.os.path.transform_to_relative_path(path)

    flags &= 0xffffffff
    mode &= 0xffffffff

    idx = next((i for i in range(NR_OPEN) if ql.os.fd[i] is None), -1)

    if idx == -1:
        regreturn = -EMFILE
    else:
        try:
            if ql.arch.type == QL_ARCH.ARM and ql.os.type != QL_OS.QNX:
                mode = 0

            flags = ql_open_flag_mapping(ql, flags)
            ql.os.fd[idx] = ql.os.fs_mapper.open_ql_file(path, flags, mode)
            regreturn = idx
        except QlSyscallError as e:
            regreturn = - e.errno


    ql.log.debug("open(%s, 0o%o) = %d" % (relative_path, mode, regreturn))

    if regreturn >= 0 and regreturn != 2:
        ql.log.debug(f'File found: {real_path:s}')
    else:
        ql.log.debug(f'File not found {real_path:s}')

    return regreturn

def ql_syscall_creat(ql: Qiling, filename: int, mode: int):
    flags = posix_open_flags["O_WRONLY"] | posix_open_flags["O_CREAT"] | posix_open_flags["O_TRUNC"]

    path = ql.os.utils.read_cstring(filename)
    real_path = ql.os.path.transform_to_real_path(path)
    relative_path = ql.os.path.transform_to_relative_path(path)

    flags &= 0xffffffff
    mode &= 0xffffffff

    idx = next((i for i in range(NR_OPEN) if ql.os.fd[i] is None), -1)

    if idx == -1:
        regreturn = -ENOMEM 
    else:
        try:
            if ql.arch.type == QL_ARCH.ARM:
                mode = 0

            flags = ql_open_flag_mapping(ql, flags)
            ql.os.fd[idx] = ql.os.fs_mapper.open_ql_file(path, flags, mode)
            regreturn = idx
        except QlSyscallError as e:
            regreturn = -e.errno

    ql.log.debug("creat(%s, 0o%o) = %d" % (relative_path, mode, regreturn))

    if regreturn >= 0 and regreturn != 2:
        ql.log.debug(f'File found: {real_path:s}')
    else:
        ql.log.debug(f'File not found {real_path:s}')

    return regreturn

def ql_syscall_openat(ql: Qiling, fd: int, path: int, flags: int, mode: int):
    file_path = ql.os.utils.read_cstring(path)
    # real_path = ql.os.path.transform_to_real_path(path)
    # relative_path = ql.os.path.transform_to_relative_path(path)

    flags &= 0xffffffff
    mode &= 0xffffffff

    idx = next((i for i in range(NR_OPEN) if ql.os.fd[i] is None), -1)

    if idx == -1:
        regreturn = -EMFILE
    else:
        try:
            if ql.arch.type == QL_ARCH.ARM:
                mode = 0

            flags = ql_open_flag_mapping(ql, flags)
            fd = ql.unpacks(ql.pack(fd))

            if 0 <= fd < NR_OPEN:
                fobj = ql.os.fd[fd]
                # ql_file object or QlFsMappedObject
                if hasattr(fobj, "fileno") and hasattr(fobj, "name"):
                    if not Path.is_absolute(Path(file_path)):
                        file_path = Path(fobj.name) / Path(file_path)

            ql.os.fd[idx] = ql.os.fs_mapper.open_ql_file(file_path, flags, mode)

            regreturn = idx
        except QlSyscallError as e:
            regreturn = -e.errno
            
    ql.log.debug(f'openat(fd = {fd:d}, path = {file_path}, mode = {mode:#o}) = {regreturn:d}')

    return regreturn


def ql_syscall_fcntl(ql: Qiling, fd: int, cmd: int, arg: int):
    if fd not in range(NR_OPEN):
        return -EBADF

    f = ql.os.fd[fd]

    if f is None:
        return -EBADF

    if cmd == F_DUPFD:
        if arg not in range(NR_OPEN):
            regreturn = -EINVAL

        for idx in range(arg, len(ql.os.fd)):
            if ql.os.fd[idx] is None:
                ql.os.fd[idx] = f.dup()
                regreturn = idx
                break
        else:
            regreturn = -EMFILE

    elif cmd == F_GETFD:
        regreturn = getattr(f, "close_on_exec", 0)

    elif cmd == F_SETFD:
        f.close_on_exec = 1 if arg & FD_CLOEXEC else 0
        regreturn = 0

    elif cmd == F_GETFL:
        regreturn = f.fcntl(cmd, arg)

    elif cmd == F_SETFL:
        f.fcntl(cmd, arg)
        regreturn = 0

    else:
        regreturn = -1

    return regreturn


def ql_syscall_fcntl64(ql: Qiling, fd: int, cmd: int, arg: int):
    if fd not in range(NR_OPEN):
        return -1

    f = ql.os.fd[fd]

    if f is None:
        return -1

    # https://linux.die.net/man/2/fcntl64
    if cmd == F_DUPFD:
        if arg not in range(NR_OPEN):
            regreturn = -1

        for idx in range(arg, len(ql.os.fd)):
            if ql.os.fd[idx] is None:
                ql.os.fd[idx] = f.dup()
                regreturn = idx
                break
        else:
            regreturn = -1

    elif cmd == F_GETFL:
        regreturn = 2

    elif cmd == F_SETFL:
        if isinstance(f, ql_socket):
            f.fcntl(cmd, arg)
        regreturn = 0

    elif cmd == F_GETFD:
        regreturn = 2

    elif cmd == F_SETFD:
        regreturn = 0

    else:
        regreturn = 0

    return regreturn


def ql_syscall_flock(ql: Qiling, fd: int, operation: int):
    # Should always return 0, we don't need a actual file lock

    return 0


def ql_syscall_rename(ql: Qiling, oldname_buf: int, newname_buf: int):
    """
    rename(const char *oldpath, const char *newpath)
    description: change the name or location of a file
    ret value: On success, zero is returned. On error, -1 is returned
    """
    regreturn = 0  # default value is success
    oldpath = ql.os.utils.read_cstring(oldname_buf)
    newpath = ql.os.utils.read_cstring(newname_buf)

    ql.log.debug(f"rename() path: {oldpath} -> {newpath}")

    old_realpath = ql.os.path.transform_to_real_path(oldpath)
    new_realpath = ql.os.path.transform_to_real_path(newpath)

    if old_realpath == new_realpath:
        # do nothing, just return success
        return regreturn

    try:
        os.rename(old_realpath, new_realpath)
    except OSError:
        ql.log.exception(f"rename(): {newpath} exists!")
        regreturn = -1

    return regreturn