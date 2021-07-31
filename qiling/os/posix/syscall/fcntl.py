#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.const import *
from qiling.os.linux.thread import *
from qiling.os.posix.filestruct import *
from qiling.os.filestruct import *
from qiling.os.posix.const import *
from qiling.os.posix.const_mapping import *
from qiling.exception import *

def ql_syscall_open(ql: Qiling, filename, flags, mode, *args, **kw):
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
        ql.log.debug("File Found: %s" % real_path)
    else:
        ql.log.debug("File Not Found %s" % real_path)
    return regreturn

def ql_syscall_creat(ql: Qiling, filename, mode, *args, **kw):
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
        ql.log.debug("File Found: %s" % real_path)
    else:
        ql.log.debug("File Not Found %s" % real_path)
    return regreturn

def ql_syscall_openat(ql: Qiling, fd, path, flags, mode, *args, **kw):
    path = ql.os.utils.read_cstring(path)
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

            ql.os.fd[idx] = ql.os.fs_mapper.open_ql_file(path, flags, mode, dir_fd)
            regreturn = idx
        except QlSyscallError as e:
            regreturn = -e.errno

    ql.log.debug(f'openat(fd = {fd:d}, path = {path}, flags = {open_flags_mapping(flags, ql.archtype)}, mode = {mode:#o}) = {regreturn:d}')

    return regreturn


def ql_syscall_fcntl(ql: Qiling, fcntl_fd, fcntl_cmd, fcntl_arg, *args, **kw):
    if not (0 <= fcntl_fd < NR_OPEN) or \
            ql.os.fd[fcntl_fd] == 0:
        return -EBADF

    f = ql.os.fd[fcntl_fd]
    
    if fcntl_cmd == F_DUPFD:
        if 0 <= fcntl_arg < NR_OPEN:            
            for idx, val in enumerate(ql.os.fd):
                if val == 0 and idx >= fcntl_arg:
                    new_fd = ql.os.fd[fcntl_fd].dup()
                    ql.os.fd[idx] = new_fd
                    regreturn = idx
                    break
            else:
                regreturn = -EMFILE
        else:
            regreturn = -EINVAL

    elif fcntl_cmd == F_GETFD:
        regreturn = getattr(f, "close_on_exec", 0)

    elif fcntl_cmd == F_SETFD:
        f.close_on_exec = 1 if fcntl_arg & FD_CLOEXEC else 0
        regreturn = 0

    elif fcntl_cmd == F_GETFL:
        regreturn = ql.os.fd[fcntl_fd].fcntl(fcntl_cmd, fcntl_arg)        

    elif fcntl_cmd == F_SETFL:
        ql.os.fd[fcntl_fd].fcntl(fcntl_cmd, fcntl_arg)
        regreturn = 0

    else:
        regreturn = -1

    return regreturn


def ql_syscall_fcntl64(ql: Qiling, fcntl_fd, fcntl_cmd, fcntl_arg, *args, **kw):

    # https://linux.die.net/man/2/fcntl64
    if fcntl_cmd == F_DUPFD:
        if 0 <= fcntl_arg < NR_OPEN and 0 <= fcntl_fd < NR_OPEN:
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


def ql_syscall_rename(ql: Qiling, oldname_buf, newname_buf, *args, **kw):
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
        regreturn = 0
    except OSError:
        ql.log.exception(f"rename(): {newpath} is exist!")
        regreturn = -1

    return regreturn

