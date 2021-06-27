#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


from qiling.const import *
from qiling.os.linux.thread import *
from qiling.os.posix.filestruct import *
from qiling.os.filestruct import *
from qiling.os.posix.const import *
from qiling.os.posix.const_mapping import *
from qiling.exception import *


def ql_syscall_open(ql, filename, flags, mode, *args, **kw):
    path = ql.mem.string(filename)
    real_path = ql.os.path.transform_to_real_path(path)
    relative_path = ql.os.path.transform_to_relative_path(path)

    flags = flags & 0xffffffff
    mode = mode & 0xffffffff

    for i in range(256):
        if ql.os.fd[i] == 0:
            idx = i
            break
    else:
        idx = -1

    if idx == -1:
        # errno ENOMEM Insufficient kernel memory was available.
        regreturn = -12 
    else:
        try:
            if ql.archtype== QL_ARCH.ARM:
                mode = 0

            flags = ql_open_flag_mapping(ql, flags)
            ql.os.fd[idx] = ql.os.fs_mapper.open_ql_file(path, flags, mode)
            regreturn = idx
        except QlSyscallError as e:
            regreturn = - e.errno

    ql.log.debug("open(%s, %s, 0o%o) = %d" % (relative_path, open_flags_mapping(flags, ql.archtype), mode, regreturn))

    if regreturn >= 0 and regreturn != 2:
        ql.log.debug("File Found: %s" % real_path)
    else:
        ql.log.debug("File Not Found %s" % real_path)
    return regreturn


def ql_syscall_openat(ql, openat_fd, openat_path, openat_flags, openat_mode, *args, **kw):
    openat_fd = ql.unpacks(ql.pack(openat_fd))
    openat_path = ql.mem.string(openat_path)

    real_path = ql.os.path.transform_to_real_path(openat_path)
    relative_path = ql.os.path.transform_to_relative_path(openat_path)

    openat_flags = openat_flags & 0xffffffff
    openat_mode = openat_mode & 0xffffffff

    for i in range(256):
        if ql.os.fd[i] == 0:
            idx = i
            break
    else:
        idx = -1

    if idx == -1:
        regreturn = -1
    else:
        try:
            if ql.archtype== QL_ARCH.ARM:
                mode = 0

            openat_flags = ql_open_flag_mapping(ql, openat_flags)
            ql.os.fd[idx] = ql.os.fs_mapper.open_ql_file(openat_path, openat_flags, openat_mode)
            regreturn = idx
        except QlSyscallError:
            regreturn = -1

    ql.log.debug("openat(%d, %s, %s, 0o%o) = %d" % (
    openat_fd, relative_path, open_flags_mapping(openat_flags, ql.archtype), openat_mode, regreturn))

    if regreturn >= 0 and regreturn != 2:
        ql.log.debug("File Found: %s" % real_path)
    else:
        ql.log.debug("File Not Found %s" % real_path)
    return regreturn


def ql_syscall_fcntl(ql, fcntl_fd, fcntl_cmd, fcntl_arg, *args, **kw):
    if ql.os.fd[fcntl_fd] == 0:
        return -EBADF

    f = ql.os.fd[fcntl_fd]
    
    if fcntl_cmd == F_GETFD:
        regreturn = f.close_on_exec

    elif fcntl_cmd == F_SETFD:
        f.close_on_exec = 1 if fcntl_arg & FD_CLOEXEC else 0
        regreturn = 0

    else:
        regreturn = -1

    return regreturn


def ql_syscall_fcntl64(ql, fcntl_fd, fcntl_cmd, fcntl_arg, *args, **kw):

    # https://linux.die.net/man/2/fcntl64
    if fcntl_cmd == F_DUPFD:
        if 0 <= fcntl_arg < 256 and 0 <= fcntl_fd < 256:
            if ql.os.fd[fcntl_fd] != 0:
                new_fd = ql.os.fd[fcntl_fd].dup()
                for idx, val in enumerate(ql.os.fd):
                    if val == 0 and idx >= fcntl_arg:
                        ql.os.fd[idx] = new_fd
                        regreturn = idx
                        break
            else:
                regreturn = -1
        else:
            regreturn = -1
    elif fcntl_cmd == F_GETFL:
        regreturn = 2
    elif fcntl_cmd == F_SETFL:
        if isinstance(ql.os.fd[fcntl_fd], ql_socket):
            ql.os.fd[fcntl_fd].fcntl(fcntl_cmd, fcntl_arg)
        regreturn = 0
    elif fcntl_cmd == F_GETFD:
        regreturn = 2
    elif fcntl_cmd == F_SETFD:
        regreturn = 0
    else:
        regreturn = 0

    return regreturn


def ql_syscall_flock(ql, flock_fd, flock_operation, *args, **kw):
    # Should always return 0, we don't need a actual file lock
    regreturn = 0
    return regreturn
