#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os

from qiling import Qiling
from qiling.const import QL_OS, QL_ARCH
from qiling.exception import QlSyscallError
from qiling.os.posix.const import *
from qiling.os.posix.const_mapping import ql_open_flag_mapping
from qiling.os.posix.filestruct import ql_socket

from .unistd import virtual_abspath_at, get_opened_fd


def __do_open(ql: Qiling, absvpath: str, flags: int, mode: int) -> int:
    flags &= 0xffffffff
    mode &= 0xffffffff

    # look for the next available fd slot
    idx = next((i for i in range(NR_OPEN) if ql.os.fd[i] is None), -1)

    if idx == -1:
        return -EMFILE

    if ql.arch.type is QL_ARCH.ARM and ql.os.type is not QL_OS.QNX:
        mode = 0

    # translate emulated os open flags into host os open flags
    flags = ql_open_flag_mapping(ql, flags)

    try:
        ql.os.fd[idx] = ql.os.fs_mapper.open_ql_file(absvpath, flags, mode)
    except QlSyscallError:
        return -1

    return idx


def ql_syscall_open(ql: Qiling, filename: int, flags: int, mode: int):
    vpath = ql.os.utils.read_cstring(filename)
    absvpath = ql.os.path.virtual_abspath(vpath)

    regreturn = __do_open(ql, absvpath, flags, mode)

    ql.log.debug(f'open("{absvpath}", {flags:#x}, 0{mode:o}) = {regreturn}')

    return regreturn


def ql_syscall_openat(ql: Qiling, fd: int, path: int, flags: int, mode: int):
    vpath = ql.os.utils.read_cstring(path)
    absvpath = virtual_abspath_at(ql, vpath, fd)

    regreturn = -1 if absvpath is None else __do_open(ql, absvpath, flags, mode)

    ql.log.debug(f'openat({fd:d}, "{vpath}", {flags:#x}, 0{mode:o}) = {regreturn:d}')

    return regreturn


def ql_syscall_creat(ql: Qiling, filename: int, mode: int):
    vpath = ql.os.utils.read_cstring(filename)

    # FIXME: this is broken
    flags = posix_open_flags["O_WRONLY"] | posix_open_flags["O_CREAT"] | posix_open_flags["O_TRUNC"]
    mode &= 0xffffffff

    idx = next((i for i in range(NR_OPEN) if ql.os.fd[i] is None), -1)

    if idx == -1:
        regreturn = -ENOMEM
    else:
        if ql.arch.type == QL_ARCH.ARM:
            mode = 0

        try:
            flags = ql_open_flag_mapping(ql, flags)
            ql.os.fd[idx] = ql.os.fs_mapper.open_ql_file(vpath, flags, mode)
        except QlSyscallError as e:
            regreturn = -e.errno
        else:
            regreturn = idx

    hpath = ql.os.path.virtual_to_host_path(vpath)
    absvpath = ql.os.path.virtual_abspath(vpath)

    ql.log.debug(f'creat("{absvpath}", {mode:#o}) = {regreturn}')

    if regreturn >= 0 and regreturn != 2:
        ql.log.debug(f'File found: {hpath:s}')
    else:
        ql.log.debug(f'File not found {hpath:s}')

    return regreturn


def ql_syscall_fcntl(ql: Qiling, fd: int, cmd: int, arg: int):
    f = get_opened_fd(ql.os, fd)

    if f is None:
        return -1

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
        regreturn = int(getattr(f, "close_on_exec", False))

    elif cmd == F_SETFD:
        f.close_on_exec = bool(arg & FD_CLOEXEC)
        regreturn = 0

    elif cmd == F_GETFL:
        regreturn = f.fcntl(cmd, arg)

    elif cmd == F_SETFL:
        flags = ql_open_flag_mapping(ql, arg)
        f.fcntl(cmd, flags)
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
    old_vpath = ql.os.utils.read_cstring(oldname_buf)
    new_vpath = ql.os.utils.read_cstring(newname_buf)

    old_absvpath = ql.os.path.virtual_abspath(old_vpath)

    # if has a mapping, rename the mapped vpath
    if ql.os.fs_mapper.has_mapping(old_absvpath):
        try:
            ql.os.fs_mapper.rename_mapping(old_vpath, new_vpath)
        except KeyError:
            regreturn = -1
        else:
            regreturn = 0

    # otherwise, rename the actual files
    else:
        old_hpath = ql.os.path.virtual_to_host_path(old_vpath)
        new_hpath = ql.os.path.virtual_to_host_path(new_vpath)

        # if source and target paths are identical, do nothing
        if old_hpath == new_hpath:
            return 0

        try:
            os.rename(old_hpath, new_hpath)
        except OSError:
            regreturn = -1
        else:
            regreturn = 0

    ql.log.debug(f'rename("{old_vpath}", "{new_vpath}") = {regreturn}')

    return regreturn
