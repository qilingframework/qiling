#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations

import os
import itertools
import pathlib

from typing import TYPE_CHECKING, IO, Iterator, Optional, Union

from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS
from qiling.os.posix.filestruct import ql_pipe
from qiling.os.posix.const import *
from qiling.core_hooks import QlCoreHooks

if TYPE_CHECKING:
    from qiling.os.posix.posix import QlOsPosix


def ql_syscall_exit(ql: Qiling, code: int):
    if ql.os.child_processes:
        os._exit(0)

    if ql.multithread:
        def _sched_cb_exit(cur_thread):
            ql.log.debug(f"[Thread {cur_thread.get_id()}] Terminated")
            ql.os.thread_management.stop_thread(cur_thread)
            cur_thread.exit_code = code

        td = ql.os.thread_management.cur_thread
        ql.emu_stop()
        td.sched_cb = _sched_cb_exit
    else:
        ql.os.exit_code = code
        ql.os.stop()


def ql_syscall_exit_group(ql: Qiling, code: int):
    if ql.os.child_processes:
        os._exit(0)

    if ql.multithread:
        def _sched_cb_exit(cur_thread):
            ql.log.debug(f"[Thread {cur_thread.get_id()}] Terminated")
            ql.os.thread_management.stop_thread(cur_thread)
            cur_thread.exit_code = code

        td = ql.os.thread_management.cur_thread
        ql.emu_stop()
        td.sched_cb = _sched_cb_exit
    else:
        ql.os.exit_code = code
        ql.os.stop()


def ql_syscall_alarm(ql: Qiling, seconds: int):
    return 0


def ql_syscall_issetugid(ql: Qiling):
    return 0


def __getuid(ql: Qiling):
    return ql.os.uid


def __setuid(ql: Qiling, uid: int):
    # TODO: security checks
    ql.os.uid = uid

    return 0


def __getgid(ql: Qiling):
    return ql.os.gid


def __setgid(ql: Qiling, gid: int):
    # TODO: security checks
    ql.os.gid = gid

    return 0


def ql_syscall_getuid(ql: Qiling):
    return __getuid(ql)


def ql_syscall_setuid(ql: Qiling, uid: int):
    return __setuid(ql, uid)


def ql_syscall_getuid32(ql: Qiling):
    return __getuid(ql)


def ql_syscall_setuid32(ql: Qiling, uid: int):
    return __setuid(ql, uid)


def ql_syscall_getgid(ql: Qiling):
    return __getgid(ql)


def ql_syscall_setgid(ql: Qiling, gid: int):
    return __setgid(ql, gid)


def ql_syscall_getgid32(ql: Qiling):
    return __getgid(ql)


def ql_syscall_setgid32(ql: Qiling, gid: int):
    return __setgid(ql, gid)


def ql_syscall_geteuid(ql: Qiling):
    return ql.os.euid


def ql_syscall_seteuid(ql: Qiling):
    return 0


def ql_syscall_getegid(ql: Qiling):
    return ql.os.egid


def ql_syscall_setgroups(ql: Qiling, gidsetsize: int, grouplist: int):
    return 0


def ql_syscall_setresuid(ql: Qiling):
    return 0


def ql_syscall_setresgid(ql: Qiling):
    return 0


def ql_syscall_capget(ql: Qiling, hdrp: int, datap: int):
    return 0


def ql_syscall_capset(ql: Qiling, hdrp: int, datap: int):
    return 0


def ql_syscall_kill(ql: Qiling, pid: int, sig: int):
    if sig not in range(NSIG):
        return -1   # EINVAL

    if pid > 0 and pid != ql.os.pid:
        return -1   # ESRCH

    sigaction = ql.os.sig[sig]

    # sa_handler is:
    #     SIG_DFL for the default action.
    #     SIG_IGN to ignore this signal.
    #     handler pointer

    # if sa_flags & SA_SIGINFO:
    #   call sa_sigaction instead of sa_handler

    return 0


def get_opened_fd(os: QlOsPosix, fd: int) -> Optional[IO]:
    """Retrieve a file instance by its file descriptor id.
    """

    if fd not in range(NR_OPEN):
        return None  # EBADF

    f = os.fd[fd]

    if f is None:
        return None  # EBADF

    return f


def ql_syscall_fsync(ql: Qiling, fd: int):
    f = get_opened_fd(ql.os, fd)

    if f is None:
        regreturn = -EBADF

    else:
        try:
            os.fsync(f.fileno())
        except OSError:
            regreturn = -1
        else:
            regreturn = 0

    ql.log.debug(f'fsync({fd:d}) = {regreturn}')

    return regreturn


def ql_syscall_fdatasync(ql: Qiling, fd: int):
    try:
        os.fdatasync(ql.os.fd[fd].fileno())
    except OSError:
        regreturn = -1
    else:
        regreturn = 0

    ql.log.debug(f'fdatasync({fd:d}) = {regreturn}')

    return regreturn


def virtual_abspath_at(ql: Qiling, vpath: str, dirfd: int) -> Union[int, str]:
    """Resolve the virtual absolute path based on the specified dirfd.

    Args:
        vpath: relative virtual path to resolve
        dirfd: base directory file descriptor

    Returns: the resolved absolute path, or an error code if could not resolve it
    """

    if ql.os.path.is_virtual_abspath(vpath):
        return vpath

    # <WORKAROUND>
    def __as_signed(value: int, nbits: int) -> int:
        msb = (1 << (nbits - 1))

        return -(((value & msb) << 1) - value)

    # syscall params are read as unsigned int by default. until we fix that
    # broadly, this is a workaround to turn fd into a signed value
    dirfd = __as_signed(dirfd & ((1 << 32) - 1), 32)
    # </WORKAROUND>

    if dirfd == AT_FDCWD:
        basedir = ql.os.path.cwd

    else:
        f = get_opened_fd(ql.os, dirfd)

        if f is None or not hasattr(f, 'name'):
            return -EBADF

        hpath = f.name

        if not os.path.isdir(hpath):
            return -ENOTDIR

        basedir = ql.os.path.host_to_virtual_path(hpath)

    return str(ql.os.path.PureVirtualPath(basedir, vpath))


def ql_syscall_faccessat(ql: Qiling, dirfd: int, filename: int, mode: int):
    vpath = ql.os.utils.read_cstring(filename)
    vpath_at = virtual_abspath_at(ql, vpath, dirfd)

    if isinstance(vpath_at, int):
        regreturn = vpath_at

    else:
        hpath = ql.os.path.virtual_to_host_path(vpath_at)

        if not ql.os.path.is_safe_host_path(hpath):
            raise PermissionError(f'unsafe path: {hpath}')

        regreturn = 0 if os.path.exists(hpath) else -ENOENT

    ql.log.debug(f'faccessat({dirfd:d}, "{vpath}", {mode:d}) = {regreturn}')

    return regreturn


def ql_syscall_lseek(ql: Qiling, fd: int, offset: int, origin: int):
    offset = ql.os.utils.as_signed(offset, 32)

    f = get_opened_fd(ql.os, fd)

    if f is None:
        regreturn = -EBADF

    else:
        try:
            regreturn = f.seek(offset, origin)
        except OSError:
            regreturn = -1

    ql.log.debug(f'lseek({fd:d}, {offset:#x}, {origin}) = {regreturn}')

    return regreturn


def ql_syscall__llseek(ql: Qiling, fd: int, offset_high: int, offset_low: int, result: int, whence: int):
    offset = ql.os.utils.as_signed((offset_high << 32) | offset_low, 64)

    f = get_opened_fd(ql.os, fd)

    if f is None:
        regreturn = -EBADF

    else:
        try:
            ret = f.seek(offset, whence)
        except OSError:
            regreturn = -1
        else:
            ql.mem.write_ptr(result, ret, 8)
            regreturn = 0

    ql.log.debug(f'_llseek({fd:d}, {offset_high:#x}, {offset_low:#x}, {result:#x}, {whence}) = {regreturn}')

    return regreturn


def ql_syscall_brk(ql: Qiling, inp: int):
    if inp:
        cur_brk_addr = ql.loader.brk_address
        new_brk_addr = ql.mem.align_up(inp)

        if new_brk_addr > cur_brk_addr:
            ql.log.debug(f'brk: increasing program break from {cur_brk_addr:#x} to {new_brk_addr:#x}')
            ql.mem.map(cur_brk_addr, new_brk_addr - cur_brk_addr, info="[brk]")

        elif new_brk_addr < cur_brk_addr:
            ql.log.debug(f'brk: decreasing program break from {cur_brk_addr:#x} to {new_brk_addr:#x}')
            ql.mem.unmap(new_brk_addr, cur_brk_addr - new_brk_addr)

        ql.loader.brk_address = new_brk_addr

    return ql.loader.brk_address


def ql_syscall_access(ql: Qiling, path: int, mode: int):
    vpath = ql.os.utils.read_cstring(path)
    hpath = ql.os.path.virtual_to_host_path(vpath)

    if not ql.os.path.is_safe_host_path(hpath):
        raise PermissionError(f'unsafe path: {hpath}')

    regreturn = 0 if os.path.exists(hpath) else -ENOENT

    ql.log.debug(f'access("{vpath}", 0{mode:o}) = {regreturn}')

    return regreturn


def ql_syscall_close(ql: Qiling, fd: int):
    f = get_opened_fd(ql.os, fd)

    if f is None:
        regreturn = -EBADF

    else:
        f.close()
        ql.os.fd[fd] = None
        regreturn = 0

    ql.log.debug(f'close({fd:d}) = {regreturn}')

    return regreturn


def ql_syscall_pread64(ql: Qiling, fd: int, buf: int, length: int, offt: int):
    f = get_opened_fd(ql.os, fd)

    if f is None:
        return -EBADF

    if not ql.mem.is_mapped(buf, length):
        return -EFAULT

    # https://chromium.googlesource.com/linux-syscall-support/+/2c73abf02fd8af961e38024882b9ce0df6b4d19b
    # https://chromiumcodereview.appspot.com/10910222
    if ql.arch.type is QL_ARCH.MIPS:
        offt = ql.mem.read_ptr(ql.arch.regs.arch_sp + 0x10, 8)

    try:
        pos = f.tell()
        f.seek(offt)

        data = f.read(length)
        f.seek(pos)
    except OSError:
        regreturn = -1
    else:
        ql.mem.write(buf, data)

        regreturn = len(data)

    return regreturn


def ql_syscall_read(ql: Qiling, fd: int, buf: int, length: int):
    f = get_opened_fd(ql.os, fd)

    if f is None:
        return -EBADF

    if not ql.mem.is_mapped(buf, length):
        return -EFAULT

    if not hasattr(f, 'read'):
        ql.log.debug(f'read failed since fd {fd:d} does not have a read method')
        return -EBADF

    try:
        data = f.read(length)
    except ConnectionError:
        ql.log.debug('read failed due to a connection error')
        return -EIO

    ql.mem.write(buf, data)
    ql.log.debug(f'read() CONTENT: {bytes(data)}')

    return len(data)


def ql_syscall_write(ql: Qiling, fd: int, buf: int, count: int):
    f = get_opened_fd(ql.os, fd)

    if f is None:
        return -EBADF

    if not ql.mem.is_mapped(buf, count):
        return -EFAULT

    if not hasattr(f, 'write'):
        ql.log.debug(f'write failed since fd {fd:d} does not have a write method')
        return -EBADF

    data = ql.mem.read(buf, count)

    try:
        f.write(data)
    except ConnectionError:
        ql.log.debug('write failed due to a connection error')
        return -EIO

    ql.log.debug(f'write() CONTENT: {bytes(data)}')

    return count


def __do_readlink(ql: Qiling, absvpath: str, outbuf: int) -> int:
    target = None

    # cover a few procfs pseudo files first
    if absvpath == r'/proc/self/exe':
        # note this would raise an exception if the binary is not under rootfs
        target = ql.os.path.host_to_virtual_path(ql.path)

    elif absvpath == r'/proc/self/cwd':
        target = ql.os.path.cwd

    elif absvpath == r'/proc/self/root':
        target = ql.os.path.root

    else:
        hpath = ql.os.path.virtual_to_host_path(absvpath)

        if not ql.os.path.is_safe_host_path(hpath):
            raise PermissionError(f'unsafe path: {hpath}')

        # FIXME: we do not really know how to emulated links, so we do not read them
        if os.path.exists(hpath):
            target = ''

    if target is None:
        return -ENOENT

    cstr = target.encode('utf-8')

    if cstr:
        ql.mem.write(outbuf, cstr + b'\x00')

    return len(cstr)


def ql_syscall_readlink(ql: Qiling, pathname: int, buf: int, bufsize: int):
    vpath = ql.os.utils.read_cstring(pathname)
    absvpath = ql.os.path.virtual_abspath(vpath)

    regreturn = __do_readlink(ql, absvpath, buf)

    ql.log.debug(f'readlink("{vpath}", {buf:#x}, {bufsize:#x}) = {regreturn}')

    return regreturn


def ql_syscall_readlinkat(ql: Qiling, dirfd: int, pathname: int, buf: int, bufsize: int):
    vpath = ql.os.utils.read_cstring(pathname)
    absvpath = virtual_abspath_at(ql, vpath, dirfd)

    regreturn = absvpath if isinstance(absvpath, int) else __do_readlink(ql, absvpath, buf)

    ql.log.debug(f'readlinkat({dirfd:d}, "{vpath}", {buf:#x}, {bufsize:#x}) = {regreturn}')

    return regreturn


def ql_syscall_getcwd(ql: Qiling, path_buff: int, path_buffsize: int):
    cwd = ql.os.path.cwd

    cwd_bytes = cwd.encode('utf-8') + b'\x00'
    ql.mem.write(path_buff, cwd_bytes)
    regreturn = len(cwd_bytes)

    ql.log.debug(f'getcwd("{cwd}", {path_buffsize}) = {regreturn}')

    return regreturn


def ql_syscall_chdir(ql: Qiling, path_name: int):
    vpath = ql.os.utils.read_cstring(path_name)
    hpath = ql.os.path.virtual_to_host_path(vpath)

    if not ql.os.path.is_safe_host_path(hpath):
        raise PermissionError(f'unsafe path: {hpath}')

    absvpath = ql.os.path.virtual_abspath(vpath)

    if os.path.isdir(hpath):
        ql.os.path.cwd = absvpath

        regreturn = 0
    else:
        regreturn = -ENOENT

    ql.log.debug(f'chdir("{absvpath}") = {regreturn}')

    return regreturn


def ql_syscall_getpid(ql: Qiling):
    return 0x512


def ql_syscall_getppid(ql: Qiling):
    return 0x1024


def ql_syscall_vfork(ql: Qiling):
    if ql.host.os == QL_OS.WINDOWS:
        from multiprocessing import Process

        try:
            pid = Process()
            pid = 0
        except:
            pid = -1
    else:
        pid = os.fork()

    if pid == 0:
        ql.os.child_processes = True
        ql.log.debug("vfork(): is this a child process: %r" % (ql.os.child_processes))
        regreturn = 0
    else:
        regreturn = pid

    if ql.os.thread_management:
        ql.emu_stop()

    return regreturn


def ql_syscall_fork(ql: Qiling):
    return ql_syscall_vfork(ql)


def ql_syscall_setsid(ql: Qiling):
    return os.getpid()


def ql_syscall_execve(ql: Qiling, pathname: int, argv: int, envp: int):
    vpath = ql.os.utils.read_cstring(pathname)
    hpath = ql.os.path.virtual_to_host_path(vpath)

    # is it safe to run?
    if not ql.os.path.is_safe_host_path(hpath):
        return -1   # EACCES

    # is it a file? does it exist?
    if not os.path.isfile(hpath):
        return -1   # EACCES

    def __read_ptr_array(addr: int) -> Iterator[int]:
        if addr:
            while True:
                elem = ql.mem.read_ptr(addr)

                if elem == 0:
                    break

                yield elem
                addr += ql.arch.pointersize

    def __read_str_array(addr: int) -> Iterator[str]:
        yield from (ql.os.utils.read_cstring(ptr) for ptr in __read_ptr_array(addr))

    args = list(__read_str_array(argv))

    env = {}
    for s in __read_str_array(envp):
        k, _, v = s.partition('=')
        env[k] = v

    ql.stop()
    ql.clear_ql_hooks()
    ql.mem.unmap_all()

    ql.log.debug(f'execve("{vpath}", [{", ".join(args)}], [{", ".join(f"{k}={v}" for k, v in env.items())}])')

    ql.loader.argv = args
    ql.loader.env = env
    ql._argv = [hpath] + args

    # Clean debugger to prevent port conflicts
    # ql.debugger = None

    if ql.code:
        return

    # recreate cached uc
    del ql.arch.uc
    uc = ql.arch.uc

    # propagate new uc to arch internals
    ql.arch.regs.uc = uc

    if hasattr(ql.arch, 'msr'):
        ql.arch.msr.uc = uc

    QlCoreHooks.__init__(ql, uc)

    ql.os.load()

    # close all open fd marked with 'close_on_exec'
    for i in range(NR_OPEN):
        f = ql.os.fd[i]

        if f and getattr(f, 'close_on_exec', False) and not f.closed:
            f.close()
            ql.os.fd[i] = None

    ql.loader.run()
    ql.run()


def ql_syscall_dup(ql: Qiling, oldfd: int):
    f = get_opened_fd(ql.os, oldfd)

    if f is None:
        return -EBADF

    newfd = next((i for i in range(NR_OPEN) if ql.os.fd[i] is None), -1)

    if newfd == -1:
        return -EMFILE

    ql.os.fd[newfd] = f.dup()

    ql.log.debug(f'dup({oldfd:d}) = {newfd:d}')

    return newfd


def ql_syscall_dup2(ql: Qiling, oldfd: int, newfd: int):
    f = get_opened_fd(ql.os, oldfd)

    if f is None:
        return -EBADF

    if newfd not in range(NR_OPEN):
        return -EBADF

    newslot = ql.os.fd[newfd]

    if newslot is not None:
        newslot.close()

    ql.os.fd[newfd] = f.dup()

    ql.log.debug(f'dup2({oldfd:d}, {newfd:d}) = {newfd:d}')

    return newfd


def ql_syscall_dup3(ql: Qiling, oldfd: int, newfd: int, flags: int):
    O_CLOEXEC = 0o2000000

    if oldfd == newfd:
        return -EINVAL

    f = get_opened_fd(ql.os, oldfd)

    if f is None:
        return -EBADF

    if newfd not in range(NR_OPEN):
        return -EBADF

    newslot = ql.os.fd[newfd]

    if newslot is not None:
        newslot.close()

    newf = f.dup()

    if flags & O_CLOEXEC:
        newf.close_on_exec = True

    ql.os.fd[newfd] = newf

    ql.log.debug(f'dup3({oldfd:d}, {newfd:d}, 0{flags:o}) = {newfd:d}')

    return newfd


def ql_syscall_set_tid_address(ql: Qiling, tidptr: int):
    if ql.os.thread_management:
        regreturn = ql.os.thread_management.cur_thread.id
    else:
        regreturn = os.getpid()

    return regreturn


def ql_syscall_pipe(ql: Qiling, pipefd: int):
    rd, wd = ql_pipe.open()

    unpopulated_fd = (i for i in range(NR_OPEN) if ql.os.fd[i] is None)
    idx1 = next(unpopulated_fd, -1)
    idx2 = next(unpopulated_fd, -1)

    if (idx1 == -1) or (idx2 == -1):
        return -EMFILE

    ql.os.fd[idx1] = rd
    ql.os.fd[idx2] = wd

    if ql.arch.type == QL_ARCH.MIPS:
        ql.arch.regs.v1 = idx2
        regreturn = idx1
    else:
        ql.mem.write_ptr(pipefd + 0, idx1, 4)
        ql.mem.write_ptr(pipefd + 4, idx2, 4)
        regreturn = 0

    return regreturn


def ql_syscall_nice(ql: Qiling, inc: int):
    return 0


def __do_truncate(ql: Qiling, hpath: str, length: int) -> int:
    if not ql.os.path.is_safe_host_path(hpath):
        raise PermissionError(f'unsafe path: {hpath}')

    try:
        st_size = os.path.getsize(hpath)

        if st_size > length:
            os.truncate(hpath, length)

        elif st_size < length:
            padding = length - st_size

            with open(hpath, 'a+b') as ofile:
                ofile.write(b'\x00' * padding)
    except OSError:
        return -1
    else:
        return 0


def ql_syscall_truncate(ql: Qiling, path: int, length: int):
    vpath = ql.os.utils.read_cstring(path)
    hpath = ql.os.path.virtual_to_host_path(vpath)

    regreturn = __do_truncate(ql, hpath, length)

    ql.log.debug(f'truncate("{vpath}", {length:#x}) = {regreturn}')

    return regreturn


def ql_syscall_ftruncate(ql: Qiling, fd: int, length: int):
    f = get_opened_fd(ql.os, fd)

    regreturn = -EBADF if f is None else __do_truncate(ql, f.name, length)

    ql.log.debug(f'ftruncate({fd}, {length:#x}) = {regreturn}')

    return regreturn


def __do_unlink(ql: Qiling, absvpath: str) -> int:

    def __has_opened_fd(hpath: str) -> bool:
        opened_fds = (ql.os.fd[i] for i in range(NR_OPEN) if ql.os.fd[i] is not None)
        f = next((fd for fd in opened_fds if getattr(fd, 'name', '') == hpath), None)

        return f is not None and f.closed

    hpath = ql.os.path.virtual_to_host_path(absvpath)

    if ql.os.fs_mapper.has_mapping(absvpath):
        if __has_opened_fd(hpath):
            return -1

        ql.os.fs_mapper.remove_mapping(absvpath)

    else:
        if not ql.os.path.is_safe_host_path(hpath):
            raise PermissionError(f'unsafe path: {hpath}')

        # NOTE: no idea why these are always ok to remove
        def __ok_to_remove(hpath: str) -> bool:
            path = pathlib.Path(hpath)

            return any((path.is_block_device(), path.is_fifo(), path.is_socket(), path.is_symlink()))

        if __has_opened_fd(hpath) and not __ok_to_remove(hpath):
            return -1

        try:
            os.unlink(hpath)
        except OSError:
            return -1

    return 0


def ql_syscall_unlink(ql: Qiling, pathname: int):
    vpath = ql.os.utils.read_cstring(pathname)
    absvpath = ql.os.path.virtual_abspath(vpath)

    regreturn = __do_unlink(ql, absvpath)

    ql.log.debug(f'unlink("{vpath}") = {regreturn}')

    return regreturn


def ql_syscall_unlinkat(ql: Qiling, dirfd: int, pathname: int, flags: int):
    vpath = ql.os.utils.read_cstring(pathname)
    absvpath = virtual_abspath_at(ql, vpath, dirfd)

    regreturn = absvpath if isinstance(absvpath, int) else __do_unlink(ql, absvpath)

    ql.log.debug(f'unlinkat({dirfd}, "{vpath}") = {regreturn}')

    return regreturn


# https://man7.org/linux/man-pages/man2/getdents.2.html
#    struct linux_dirent {
#        unsigned long  d_ino;     /* Inode number */
#        unsigned long  d_off;     /* Offset to next linux_dirent */
#        unsigned short d_reclen;  /* Length of this linux_dirent */
#        char           d_name[];  /* Filename (null-terminated) */
#                                  /* length is actually (d_reclen - 2 - offsetof(struct linux_dirent, d_name)) */
#        /*
#        char           pad;       // Zero padding byte
#        char           d_type;    // File type (only since Linux 2.6.4); offset is (d_reclen - 1)
#        */
#    }
#
#    struct linux_dirent64 {
#        ino64_t        d_ino;    /* 64-bit inode number */
#        off64_t        d_off;    /* 64-bit offset to next structure */
#        unsigned short d_reclen; /* Size of this dirent */
#        unsigned char  d_type;   /* File type */
#        char           d_name[]; /* Filename (null-terminated) */
#    };
def __getdents_common(ql: Qiling, fd: int, dirp: int, count: int, *, is_64: bool):
    # TODO: not sure what is the meaning of d_off, should not be 0x0
    # but works for the example code from linux manual.
    #
    # https://stackoverflow.com/questions/16714265/meaning-of-field-d-off-in-last-struct-dirent

    def _type_mapping(ent):
        methods_constants_d = {
            'is_fifo'         : 0x1,
            'is_char_device'  : 0x2,
            'is_dir'          : 0x4,
            'is_block_device' : 0x6,
            'is_file'         : 0x8,
            'is_symlink'      : 0xa,
            'is_socket'       : 0xc
        }

        ent_p = pathlib.Path(ent.path) if isinstance(ent, os.DirEntry) else ent

        for method, constant in methods_constants_d.items():
            if getattr(ent_p, method)():
                t = constant
                break
        else:
            t = 0x0 # DT_UNKNOWN

        return bytes([t])

    if ql.os.fd[fd].tell() == 0:
        n = 8 if is_64 else ql.arch.pointersize
        total_size = 0
        results = os.scandir(ql.os.fd[fd].name)
        _ent_count = 0

        for result in itertools.chain((pathlib.Path('.'), pathlib.Path('..')), results): # chain speical directories with the results
            d_ino = result.inode() if isinstance(result, os.DirEntry) else result.stat().st_ino
            d_off = 0
            d_name = (result.name if isinstance(result, os.DirEntry) else result._str).encode() + b'\x00'
            d_type = _type_mapping(result)
            d_reclen = n + n + 2 + len(d_name) + 1

            # TODO: Dirty fix for X8664 MACOS 11.6 APFS
            # For some reason MACOS return int value is 64bit
            try:
                packed_d_ino = (ql.pack(d_ino), n)
            except:
                packed_d_ino = (ql.pack64(d_ino), n)

            if is_64:
                fields = (
                    (ql.pack64(d_ino), n),
                    (ql.pack64(d_off), n),
                    (ql.pack16(d_reclen), 2),
                    (d_type, 1),
                    (d_name, len(d_name))
                )
            else:
                fields = (
                    packed_d_ino,
                    (ql.pack(d_off), n),
                    (ql.pack16(d_reclen), 2),
                    (d_name, len(d_name)),
                    (d_type, 1)
                )

            p = dirp
            for fval, flen in fields:
                ql.mem.write(p, fval)
                p += flen

            ql.log.debug(f"Write dir entries: {ql.mem.read(dirp, d_reclen)}")

            dirp += d_reclen
            total_size += d_reclen
            _ent_count += 1

        regreturn = total_size
        ql.os.fd[fd].seek(0, os.SEEK_END) # mark as end of file for dir_fd
    else:
        _ent_count = 0
        regreturn = 0

    ql.log.debug("%s(%d, /* %d entries */, 0x%x) = %d" % ("getdents64" if is_64 else "getdents", fd, _ent_count, count, regreturn))

    return regreturn


def ql_syscall_getdents(ql: Qiling, fd: int, dirp: int, count: int):
    return __getdents_common(ql, fd, dirp, count, is_64=False)


def ql_syscall_getdents64(ql: Qiling, fd: int, dirp: int, count: int):
    return __getdents_common(ql, fd, dirp, count, is_64=True)
