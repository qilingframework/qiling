#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os

from qiling import Qiling
from qiling.const import QL_OS, QL_ARCH
from qiling.exception import QlSyscallError
from qiling.os.posix.const import *
from qiling.os.posix.const_mapping import ql_open_flag_mapping, open_flags_mapping
from qiling.os.posix.filestruct import ql_socket

def ql_syscall_open(ql: Qiling, filename: int, flags: int, mode: int):
    path = ql.os.utils.read_cstring(filename)
    real_path = ql.os.path.transform_to_real_path(path)
    relative_path = ql.os.path.transform_to_relative_path(path)

    flags &= 0xffffffff
    mode &= 0xffffffff

    idx = next((i for i in range(NR_OPEN) if ql.os.fd[i] == 0), -1)

    if idx == -1:
        regreturn = -EMFILE
    else:
        try:
            if ql.archtype== QL_ARCH.ARM and ql.ostype!= QL_OS.QNX:
                mode = 0

            flags = ql_open_flag_mapping(ql, flags)
            ql.os.fd[idx] = ql.os.fs_mapper.open_ql_file(path, flags, mode)
            regreturn = idx
        except QlSyscallError as e:
            regreturn = - e.errno

    ql.log.debug("open(%s, %s, 0o%o) = %d" % (relative_path, open_flags_mapping(flags, ql.archtype), mode, regreturn))

    if regreturn >= 0 and regreturn != 2:
        ql.log.debug(f'File found: {real_path:s}')
    else:
        ql.log.debug(f'File not found {real_path:s}')

    return regreturn

def ql_syscall_creat(ql: Qiling, filename: int, mode: int):
    flags = linux_open_flags["O_WRONLY"] | linux_open_flags["O_CREAT"] | linux_open_flags["O_TRUNC"]

    path = ql.os.utils.read_cstring(filename)
    real_path = ql.os.path.transform_to_real_path(path)
    relative_path = ql.os.path.transform_to_relative_path(path)

    flags &= 0xffffffff
    mode &= 0xffffffff

    idx = next((i for i in range(NR_OPEN) if ql.os.fd[i] == 0), -1)

    if idx == -1:
        regreturn = -ENOMEM 
    else:
        try:
            if ql.archtype== QL_ARCH.ARM:
                mode = 0

            flags = ql_open_flag_mapping(ql, flags)
            ql.os.fd[idx] = ql.os.fs_mapper.open_ql_file(path, flags, mode)
            regreturn = idx
        except QlSyscallError as e:
            regreturn = -e.errno

    ql.log.debug("creat(%s, %s, 0o%o) = %d" % (relative_path, open_flags_mapping(flags, ql.archtype), mode, regreturn))

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

    idx = next((i for i in range(NR_OPEN) if ql.os.fd[i] == 0), -1)

    if idx == -1:
        regreturn = -EMFILE
    else:
        try:
            if ql.archtype== QL_ARCH.ARM:
                mode = 0

            flags = ql_open_flag_mapping(ql, flags)
            try:
                dir_fd = ql.os.fd[fd].fileno()
            except:
                dir_fd = None

            ql.os.fd[idx] = ql.os.fs_mapper.open_ql_file(file_path, flags, mode, dir_fd)
            regreturn = idx
        except QlSyscallError as e:
            regreturn = -e.errno

    ql.log.debug(f'openat(fd = {fd:d}, path = {file_path}, flags = {open_flags_mapping(flags, ql.archtype)}, mode = {mode:#o}) = {regreturn:d}')

    return regreturn


def ql_syscall_fcntl(ql: Qiling, fd: int, cmd: int, arg: int):
    if not (0 <= fd < NR_OPEN) or ql.os.fd[fd] == 0:
        return -EBADF

    f = ql.os.fd[fd]

    if cmd == F_DUPFD:
        if 0 <= arg < NR_OPEN:
            for idx, val in enumerate(ql.os.fd):
                if val == 0 and idx >= arg:
                    new_fd = ql.os.fd[fd].dup()
                    ql.os.fd[idx] = new_fd
                    regreturn = idx
                    break
            else:
                regreturn = -EMFILE
        else:
            regreturn = -EINVAL

    elif cmd == F_GETFD:
        regreturn = getattr(f, "close_on_exec", 0)

    elif cmd == F_SETFD:
        f.close_on_exec = 1 if arg & FD_CLOEXEC else 0
        regreturn = 0

    elif cmd == F_GETFL:
        regreturn = ql.os.fd[fd].fcntl(cmd, arg)

    elif cmd == F_SETFL:
        ql.os.fd[fd].fcntl(cmd, arg)
        regreturn = 0

    else:
        regreturn = -1

    return regreturn


def ql_syscall_fcntl64(ql: Qiling, fd: int, cmd: int, arg: int):

    # https://linux.die.net/man/2/fcntl64
    if cmd == F_DUPFD:
        if 0 <= arg < NR_OPEN and 0 <= fd < NR_OPEN:
            if ql.os.fd[fd] != 0:
                new_fd = ql.os.fd[fd].dup()
                for idx, val in enumerate(ql.os.fd):
                    if val == 0 and idx >= arg:
                        ql.os.fd[idx] = new_fd
                        regreturn = idx
                        break
            else:
                regreturn = -1
        else:
            regreturn = -1

    elif cmd == F_GETFL:
        regreturn = 2

    elif cmd == F_SETFL:
        if isinstance(ql.os.fd[fd], ql_socket):
            ql.os.fd[fd].fcntl(cmd, arg)
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
