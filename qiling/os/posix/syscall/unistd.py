#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os
import stat
import itertools
import pathlib

from typing import Iterator
from multiprocessing import Process

from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
from qiling.os.posix.filestruct import ql_pipe
from qiling.os.posix.const import *
from qiling.os.posix.stat import Stat
from qiling.core_hooks import QlCoreHooks

def ql_syscall_exit(ql: Qiling, code: int):
    if ql.os.child_processes == True:
        os._exit(0)

    if ql.multithread:
        def _sched_cb_exit(cur_thread):
            ql.log.debug(f"[Thread {cur_thread.get_id()}] Terminated")
            cur_thread.stop()
            cur_thread.exit_code = code

        td = ql.os.thread_management.cur_thread
        ql.emu_stop()
        td.sched_cb = _sched_cb_exit
    else:
        ql.os.exit_code = code
        ql.os.stop()


def ql_syscall_exit_group(ql: Qiling, code: int):
    if ql.os.child_processes == True:
        os._exit(0)

    if ql.multithread:
        def _sched_cb_exit(cur_thread):
            ql.log.debug(f"[Thread {cur_thread.get_id()}] Terminated")
            cur_thread.stop()
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


def ql_syscall_getuid(ql: Qiling):
    return 0


def ql_syscall_getuid32(ql: Qiling):
    return 0


def ql_syscall_getgid32(ql: Qiling):
    return 0


def ql_syscall_geteuid(ql: Qiling):
    return 0


def ql_syscall_getegid(ql: Qiling):
    return 0


def ql_syscall_getgid(ql: Qiling):
    return 0


def ql_syscall_setgroups(ql: Qiling, gidsetsize: int, grouplist: int):
    return 0


def ql_syscall_setgid(ql: Qiling):
    return 0


def ql_syscall_setgid32(ql: Qiling):
    return 0


def ql_syscall_setuid(ql: Qiling):
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
    return 0

def ql_syscall_faccessat(ql: Qiling, dfd: int, filename: int, mode: int):
    access_path = ql.os.utils.read_cstring(filename)
    real_path = ql.os.path.transform_to_real_path(access_path)

    if not os.path.exists(real_path):
        regreturn = -1

    elif stat.S_ISFIFO(Stat(real_path).st_mode):
        regreturn = 0

    else:
        regreturn = -1

    if regreturn == -1:
        ql.log.debug(f'File not found or skipped: {access_path}')
    else:
        ql.log.debug(f'File found: {access_path}')

    return regreturn


def ql_syscall_lseek(ql: Qiling, fd: int, offset: int, lseek_origin: int):
    if 0 <= fd < NR_OPEN and ql.os.fd[fd] != 0:
        offset = ql.unpacks(ql.pack(offset))

        try:
            regreturn = ql.os.fd[fd].lseek(offset, lseek_origin)
        except OSError:
            regreturn = -1
        else:
            regreturn = 0
    else:
        regreturn = -EBADF

    # ql.log.debug("lseek(fd = %d, ofset = 0x%x, origin = 0x%x) = %d" % (lseek_fd, lseek_ofset, lseek_origin, regreturn))

    return regreturn


def ql_syscall__llseek(ql: Qiling, fd: int, offset_high: int, offset_low: int, result: int, whence: int):
    # treat offset as a signed value
    offset = ql.unpack64s(ql.pack64((offset_high << 32) | offset_low))
    origin = whence

    try:
        ret = ql.os.fd[fd].lseek(offset, origin)
    except OSError:
        regreturn = -1
    else:
        ql.mem.write(result, ql.pack64(ret))
        regreturn = 0

    # ql.log.debug("_llseek(%d, 0x%x, 0x%x, 0x%x) = %d" % (fd, offset_high, offset_low, origin, regreturn))

    return regreturn


def ql_syscall_brk(ql: Qiling, inp: int):
    # current brk_address will be modified if inp is not NULL(zero)
    # otherwise, just return current brk_address

    if inp:
        new_brk_addr = ((inp + 0xfff) // 0x1000) * 0x1000

        if inp > ql.loader.brk_address: # increase current brk_address if inp is greater
            ql.mem.map(ql.loader.brk_address, new_brk_addr - ql.loader.brk_address, info="[brk]")

        elif inp < ql.loader.brk_address: # shrink current bkr_address to inp if its smaller
            ql.mem.unmap(new_brk_addr, ql.loader.brk_address - new_brk_addr)

        ql.loader.brk_address = new_brk_addr

    return ql.loader.brk_address


def ql_syscall_access(ql: Qiling, path: int, mode: int):
    file_path = ql.os.utils.read_cstring(path)
    real_path = ql.os.path.transform_to_real_path(file_path)
    relative_path = ql.os.path.transform_to_relative_path(file_path)

    regreturn = 0 if os.path.exists(real_path) else -1

    # ql.log.debug("access(%s, 0x%x) = %d " % (relative_path, access_mode, regreturn))

    if regreturn == 0:
        ql.log.debug(f'File found: {relative_path}')
    else:
        ql.log.debug(f'No such file or directory: {relative_path}')

    return regreturn


def ql_syscall_close(ql: Qiling, fd: int):
    if 0 <= fd < NR_OPEN and ql.os.fd[fd] != 0:
        ql.os.fd[fd].close()
        ql.os.fd[fd] = 0
        regreturn = 0
    else:
        regreturn = -1

    return regreturn


def ql_syscall_pread64(ql: Qiling, fd: int, buf: int, length: int, offt: int):
    # https://chromium.googlesource.com/linux-syscall-support/+/2c73abf02fd8af961e38024882b9ce0df6b4d19b
    # https://chromiumcodereview.appspot.com/10910222
    if ql.archtype == QL_ARCH.MIPS:
        offt = ql.unpack64(ql.mem.read(ql.reg.arch_sp + 0x10, 8))

    if 0 <= fd < NR_OPEN and ql.os.fd[fd] != 0:
        try:
            pos = ql.os.fd[fd].tell()
            ql.os.fd[fd].lseek(offt)

            data = ql.os.fd[fd].read(length)
            ql.os.fd[fd].lseek(pos)

            ql.mem.write(buf, data)
            regreturn = len(data)
        except:
            regreturn = -1
    else:
        regreturn = -1

    return regreturn


def ql_syscall_read(ql: Qiling, fd, buf: int, length: int):
    if 0 <= fd < NR_OPEN and ql.os.fd[fd] != 0:
        try:
            data = ql.os.fd[fd].read(length)
            ql.mem.write(buf, data)
        except:
            regreturn = -EBADF
        else:
            ql.log.debug(f'read() CONTENT: {data!r}')
            regreturn = len(data)

    else:
        regreturn = -EBADF

    return regreturn


def ql_syscall_write(ql: Qiling, fd: int, buf: int, count: int):
    try:
        data = ql.mem.read(buf, count)
    except:
        regreturn = -1
    else:
        ql.log.debug(f'write() CONTENT: {data.decode()!r}')

        if hasattr(ql.os.fd[fd], 'write'):
            ql.os.fd[fd].write(data)
        else:
            ql.log.warning(f'write failed since fd {fd:d} does not have a write method')

        regreturn = count

    return regreturn


def ql_syscall_readlink(ql: Qiling, path_name: int, path_buff: int, path_buffsize: int):
    pathname = ql.os.utils.read_cstring(path_name)
    # pathname = str(pathname, 'utf-8', errors="ignore")
    real_path = ql.os.path.transform_to_link_path(pathname)
    relative_path = ql.os.path.transform_to_relative_path(pathname)

    if not os.path.exists(real_path):
        regreturn = -1

    elif relative_path == r'/proc/self/exe':
        localpath = os.path.abspath(ql.path)
        localpath = bytes(localpath, 'utf-8') + b'\x00'

        ql.mem.write(path_buff, localpath)
        regreturn = len(localpath) - 1

    else:
        regreturn = 0

    ql.log.debug("readlink(%s, 0x%x, 0x%x) = %d" % (relative_path, path_buff, path_buffsize, regreturn))

    return regreturn


def ql_syscall_getcwd(ql: Qiling, path_buff: int, path_buffsize: int):
    localpath = ql.os.path.transform_to_relative_path('./')
    localpath = bytes(localpath, 'utf-8') + b'\x00'

    ql.mem.write(path_buff, localpath)
    regreturn = len(localpath)

    pathname = ql.os.utils.read_cstring(path_buff)
    # pathname = str(pathname, 'utf-8', errors="ignore")

    ql.log.debug("getcwd(%s, 0x%x) = %d" % (pathname, path_buffsize, regreturn))

    return regreturn


def ql_syscall_chdir(ql: Qiling, path_name: int):
    pathname = ql.os.utils.read_cstring(path_name)
    real_path = ql.os.path.transform_to_real_path(pathname)
    relative_path = ql.os.path.transform_to_relative_path(pathname)

    if os.path.exists(real_path) and os.path.isdir(real_path):
        if ql.os.thread_management:
            ql.os.thread_management.cur_thread.path.cwd = relative_path
        else:
            ql.os.path.cwd = relative_path

        regreturn = 0
        ql.log.debug("chdir(%s) = %d"% (relative_path, regreturn))
    else:
        regreturn = -1
        ql.log.warning("chdir(%s) = %d : not found" % (relative_path, regreturn))

    return regreturn


def ql_syscall_readlinkat(ql: Qiling, dfd: int, path: int, buf: int, bufsize: int):
    pathname = ql.os.utils.read_cstring(path)
    # pathname = str(pathname, 'utf-8', errors="ignore")
    real_path = ql.os.path.transform_to_link_path(pathname)
    relative_path = ql.os.path.transform_to_relative_path(pathname)

    if not os.path.exists(real_path):
        regreturn = -1

    elif relative_path == r'/proc/self/exe':
        localpath = os.path.abspath(ql.path)
        localpath = bytes(localpath, 'utf-8') + b'\x00'

        ql.mem.write(buf, localpath)
        regreturn = len(localpath) -1
    else:
        regreturn = 0

    return regreturn


def ql_syscall_getpid(ql: Qiling):
    return 0x512


def ql_syscall_getppid(ql: Qiling):
    return 0x1024


def ql_syscall_vfork(ql: Qiling):
    if ql.platform == QL_OS.WINDOWS:
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
    file_path = ql.os.utils.read_cstring(pathname)
    real_path = ql.os.path.transform_to_real_path(file_path)

    def __read_str_array(addr: int) -> Iterator[str]:
        if addr:
            while True:
                elem = ql.mem.read_ptr(addr)

                if elem == 0:
                    break

                yield ql.os.utils.read_cstring(elem)
                addr += ql.pointersize

    args = [s for s in __read_str_array(argv)]

    env = {}
    for s in __read_str_array(envp):
        k, _, v = s.partition('=')
        env[k] = v

    ql.emu_stop()

    ql.log.debug(f'execve({file_path}, [{", ".join(args)}], [{", ".join(f"{k}={v}" for k, v in env.items())}])')

    ql.loader.argv = args
    ql.loader.env = env
    ql._path = real_path
    ql.mem.map_info = []
    ql.clear_ql_hooks()

    # Clean debugger to prevent port conflicts
    ql.debugger = None

    if ql.code:
        return

    ql._uc = ql.arch.init_uc
    QlCoreHooks.__init__(ql, ql._uc)

    ql.os.load()
    ql.loader.run()
    ql.run()


def ql_syscall_dup(ql: Qiling, oldfd: int):
    regreturn = -EBADF

    if oldfd in range(256):
        if ql.os.fd[oldfd] != 0:
            newfd = ql.os.fd[oldfd].dup()

            for i, val in enumerate(ql.os.fd):
                if val == 0:
                    ql.os.fd[i] = newfd
                    regreturn = i
                    break
            else:
                regreturn = -EMFILE

    return regreturn


def ql_syscall_dup2(ql: Qiling, fd: int, newfd: int):
    if 0 <= fd < NR_OPEN and ql.os.fd[fd] != 0:
        if 0 <= newfd < NR_OPEN:
            ql.os.fd[newfd] = ql.os.fd[fd].dup()
            return newfd

    return -EBADF


def ql_syscall_dup3(ql: Qiling, fd, newfd: int, flags: int):
    if 0 <= fd < NR_OPEN and ql.os.fd[fd] != 0:
        if 0 <= newfd < NR_OPEN:
            ql.os.fd[newfd] = ql.os.fd[fd].dup()
            return newfd

    return -1

def ql_syscall_set_tid_address(ql: Qiling, tidptr: int):
    if ql.os.thread_management:
        ql.os.thread_management.cur_thread.set_clear_child_tid_addr(tidptr)

        regreturn = ql.os.thread_management.cur_thread.id
    else:
        regreturn = os.getpid()

    return regreturn


def ql_syscall_pipe(ql: Qiling, pipefd: int):
    rd, wd = ql_pipe.open()

    idx1 = -1
    idx2 = -1

    for i in range(NR_OPEN):
        if ql.os.fd[i] == 0:
            idx1 = i
            break

    if idx1 == -1:
        regreturn = -1
    else:
        for i in range(NR_OPEN):
            if ql.os.fd[i] == 0 and i != idx1:
                idx2 = i
                break

        if idx2 == -1:
            regreturn = -1
        else:
            ql.os.fd[idx1] = rd
            ql.os.fd[idx2] = wd

            if ql.archtype== QL_ARCH.MIPS:
                ql.reg.v1 = idx2
                regreturn = idx1
            else:
                ql.mem.write(pipefd + 0, ql.pack32(idx1))
                ql.mem.write(pipefd + 4, ql.pack32(idx2))
                regreturn = 0

    ql.log.debug("pipe(%x, [%d, %d]) = %d" % (pipefd, idx1, idx2, regreturn))

    return regreturn


def ql_syscall_nice(ql: Qiling, inc: int):
    return 0


def ql_syscall_truncate(ql: Qiling, path: int, length: int):
    file_path = ql.os.utils.read_cstring(path)
    real_path = ql.os.path.transform_to_real_path(file_path)
    st_size = Stat(real_path).st_size

    try:
        if st_size >= length:
            os.truncate(real_path, length)

        else:
            padding = length - st_size

            with open(real_path, 'a+b') as ofile:
                ofile.write(b'\x00' * padding)
    except:
        regreturn = -1
    else:
        regreturn = 0

    ql.log.debug('truncate(%s, 0x%x) = %d' % (file_path, length, regreturn))

    return regreturn


def ql_syscall_ftruncate(ql: Qiling, fd: int, length: int):
    real_path = ql.os.fd[fd].name
    st_size = Stat(real_path).st_size

    try:
        if st_size >= length:
            os.truncate(real_path, length)

        else:
            padding = length - st_size

            with open(real_path, 'a+b') as ofile:
                ofile.write(b'\x00' * padding)
    except:
        regreturn = -1
    else:
        regreturn = 0

    ql.log.debug("ftruncate(%d, 0x%x) = %d" % (fd, length, regreturn))

    return regreturn


def ql_syscall_unlink(ql: Qiling, pathname: int):
    file_path = ql.os.utils.read_cstring(pathname)
    real_path = ql.os.path.transform_to_real_path(file_path)

    opened_fds = [getattr(ql.os.fd[i], 'name', None) for i in range(NR_OPEN) if ql.os.fd[i] != 0]
    path = pathlib.Path(real_path)

    if any((real_path not in opened_fds, path.is_block_device(), path.is_fifo(), path.is_socket(), path.is_symlink())):
        try:
            os.unlink(real_path)
        except FileNotFoundError:
            ql.log.debug('No such file or directory')
            regreturn = -1
        except:
            regreturn = -1
        else:
            regreturn = 0

    else:
        regreturn = -1

    ql.log.debug("unlink(%s) = %d" % (file_path, regreturn))

    return regreturn


def ql_syscall_unlinkat(ql: Qiling, fd: int, pathname: int):
    file_path = ql.os.utils.read_cstring(pathname)
    real_path = ql.os.path.transform_to_real_path(file_path)

    try:
        dir_fd = ql.os.fd[fd].fileno()
    except:
        dir_fd = None

    try:
        if dir_fd is None:
            os.unlink(real_path)
        else:
            os.unlink(file_path, dir_fd=dir_fd)
    except OSError as e:
        regreturn = -e.errno
    else:
        regreturn = 0

    ql.log.debug("unlinkat(fd = %d, path = '%s') = %d" % (fd, file_path, regreturn))

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
        n = ql.pointersize
        total_size = 0
        results = os.scandir(ql.os.fd[fd].name)
        _ent_count = 0

        for result in itertools.chain((pathlib.Path('.'), pathlib.Path('..')), results): # chain speical directories with the results
            d_ino = result.inode() if isinstance(result, os.DirEntry) else result.stat().st_ino
            d_off = 0
            d_name = (result.name if isinstance(result, os.DirEntry) else result._str).encode() + b'\x00'
            d_type = _type_mapping(result)
            d_reclen = n + n + 2 + len(d_name) + 1

            if is_64:
                fields = (
                    (ql.pack(d_ino), n),
                    (ql.pack(d_off), n),
                    (ql.pack16(d_reclen), 2),
                    (d_type, 1),
                    (d_name, len(d_name))
                )
            else:
                fields = (
                    (ql.pack(d_ino), n),
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
        ql.os.fd[fd].lseek(0, os.SEEK_END) # mark as end of file for dir_fd
    else:
        _ent_count = 0
        regreturn = 0

    ql.log.debug("%s(%d, /* %d entries */, 0x%x) = %d" % ("getdents64" if is_64 else "getdents", fd, _ent_count, count, regreturn))

    return regreturn


def ql_syscall_getdents(ql: Qiling, fd: int, dirp: int, count: int):
    return __getdents_common(ql, fd, dirp, count, is_64=False)

def ql_syscall_getdents64(ql: Qiling, fd: int, dirp: int, count: int):
    return __getdents_common(ql, fd, dirp, count, is_64=True)
