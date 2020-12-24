#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import stat, logging, itertools, pathlib

from multiprocessing import Process

from qiling.const import *
from qiling.os.linux.thread import *
from qiling.const import *
from qiling.os.posix.filestruct import *
from qiling.os.filestruct import *
from qiling.os.posix.const_mapping import *
from qiling.exception import *
from qiling.os.stat import *

def ql_syscall_exit(ql, exit_code, *args, **kw):
    

    logging.info("exit(%u) = %u" % (exit_code, exit_code))

    if ql.os.child_processes == True:
        os._exit(0)

    if ql.multithread:
        def _sched_cb_exit(cur_thread):
            logging.debug(f"[Thread {cur_thread.get_id()}] Terminated.")
            cur_thread.status = THREAD_STATUS_TERMINATED
            cur_thread.stop()
            cur_thread.exit_code = exit_code
        td = ql.os.thread_management.cur_thread
        ql.emu_stop()
        td.sched_cb = _sched_cb_exit
    else:
        ql.os.exit_code = exit_code
        ql.os.stop()


def ql_syscall_exit_group(ql, exit_code, *args, **kw):
    ql.os.exit_code = exit_code

    logging.info("exit_group(%u)" % ql.os.exit_code)

    if ql.os.child_processes == True:
        os._exit(0)

    ql.os.stop()


def ql_syscall_alarm(ql, alarm_seconds, *args, **kw):
    regreturn = 0
    logging.info("alarm(%d) = %d" % (alarm_seconds, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_issetugid(ql, *args, **kw):
    UGID = ql.os.uid
    logging.info("issetugid(%i)" % UGID)
    regreturn = UGID
    ql.os.definesyscall_return(regreturn)


def ql_syscall_getuid(ql, *args, **kw):
    UID = ql.os.uid
    logging.info("getuid(%i)" % UID)
    regreturn = UID
    ql.os.definesyscall_return(regreturn)


def ql_syscall_getuid32(ql, *args, **kw):
    UID = ql.os.uid
    logging.info("getuid32(%i)" % UID)
    regreturn = UID
    ql.os.definesyscall_return(regreturn)


def ql_syscall_getgid32(ql, *args, **kw):
    GID = ql.os.gid
    logging.info("getgid32(%i)" % GID)
    regreturn = GID
    ql.os.definesyscall_return(regreturn)


def ql_syscall_geteuid(ql, *args, **kw):
    EUID = ql.os.uid
    logging.info("geteuid(%i)" % EUID)
    regreturn = EUID
    ql.os.definesyscall_return(regreturn)


def ql_syscall_getegid(ql, *args, **kw):
    EGID = ql.os.gid
    logging.info("getegid(%i)" % EGID)
    regreturn = EGID
    ql.os.definesyscall_return(regreturn)


def ql_syscall_getgid(ql, *args, **kw):
    GID = ql.os.gid
    logging.info("getgid(%i)" % GID)
    regreturn = GID
    ql.os.definesyscall_return(regreturn)


def ql_syscall_setgroups(ql, gidsetsize, grouplist, *args, **kw):
    GID = ql.os.gid
    regreturn = GID
    logging.info("setgroups(0x%x, 0x%x) = %d" % (gidsetsize, grouplist, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_setgid(ql, *args, **kw):
    GID = ql.os.gid
    logging.info("setgid(%i)" % GID)
    regreturn = GID
    ql.os.definesyscall_return(regreturn)


def ql_syscall_setgid32(ql, *args, **kw):
    GID = ql.os.gid
    logging.info("setgid32(%i)" % GID)
    regreturn = GID
    ql.os.definesyscall_return(regreturn)    


def ql_syscall_setuid(ql, *args, **kw):
    UID = ql.os.uid
    logging.info("setuid(%i)" % UID)
    regreturn = UID
    ql.os.definesyscall_return(regreturn)


def ql_syscall_faccessat(ql, faccessat_dfd, faccessat_filename, faccessat_mode, *args, **kw):

    access_path = ql.mem.string(faccessat_filename)
    real_path = ql.os.transform_to_real_path(access_path)
    relative_path = ql.os.transform_to_relative_path(access_path)

    regreturn = -1
    if os.path.exists(real_path) == False:
        regreturn = -1
    elif stat.S_ISFIFO(Stat(real_path).st_mode):
        regreturn = 0
    else:
        regreturn = -1

    ql.os.definesyscall_return(regreturn)
    logging.info("facccessat (%d, 0x%x, 0x%x) = %d" %(faccessat_dfd, faccessat_filename, faccessat_mode, regreturn))

    if regreturn == -1:
        logging.debug("[!] File Not Found or Skipped: %s" % access_path)
    else:
        logging.debug("[+] File Found: %s" % access_path)


def ql_syscall_lseek(ql, lseek_fd, lseek_ofset, lseek_origin, *args, **kw):
    lseek_ofset = ql.unpacks(ql.pack(lseek_ofset))
    regreturn = 0
    logging.debug("lseek(%d, 0x%x, 0x%x) = %d" % (lseek_fd, lseek_ofset, lseek_origin, regreturn))
    try:
        regreturn = ql.os.fd[lseek_fd].lseek(lseek_ofset, lseek_origin)
    except OSError:
        regreturn = -1
    logging.info("lseek(%d, 0x%x, 0x%x) = %d" % (lseek_fd, lseek_ofset, lseek_origin, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall__llseek(ql, fd, offset_high, offset_low, result, whence, *args, **kw):
    offset = offset_high << 32 | offset_low
    origin = whence
    regreturn = 0
    logging.info("_llseek(%d, 0x%x, 0x%x, 0x%x) = %d" % (fd, offset_high, offset_low, origin, regreturn))
    try:
        ret = ql.os.fd[fd].lseek(offset, origin)
    except OSError:
        regreturn = -1
    #regreturn = 0 if ret >= 0 else -1
    if regreturn == 0:
        ql.mem.write(result, ql.pack64(ret))

    logging.info("_llseek(%d, 0x%x, 0x%x, 0x%x) = %d" % (fd, offset_high, offset_low, origin, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_brk(ql, brk_input, *args, **kw):
    # current brk_address will be modified if brk_input is not NULL(zero)
    # otherwise, just return current brk_address

    logging.info("brk(0x%x)" % brk_input)

    if brk_input != 0:
        new_brk_addr = ((brk_input + 0xfff) // 0x1000) * 0x1000

        if brk_input > ql.loader.brk_address: # increase current brk_address if brk_input is greater
            ql.mem.map(ql.loader.brk_address, new_brk_addr - ql.loader.brk_address, info="[brk]")

        elif brk_input < ql.loader.brk_address: # shrink current bkr_address to brk_input if its smaller
            ql.mem.unmap(new_brk_addr, ql.loader.brk_address - new_brk_addr)

        ql.loader.brk_address = new_brk_addr

    regreturn = ql.loader.brk_address

    ql.os.definesyscall_return(regreturn)
    logging.debug("[+] brk return(0x%x)" % regreturn)


def ql_syscall_access(ql, access_path, access_mode, *args, **kw):
    path = (ql.mem.string(access_path))

    real_path = ql.os.transform_to_real_path(path)
    relative_path = ql.os.transform_to_relative_path(path)

    if os.path.exists(real_path) == False:
        regreturn = -1
    else:
        regreturn = 0

    ql.os.definesyscall_return(regreturn)

    logging.info("access(%s, 0x%x) = %d " % (relative_path, access_mode, regreturn))
    if regreturn == 0:
        logging.debug("[+] File found: %s" % relative_path)
    else:
        logging.debug("[!] No such file or directory")


def ql_syscall_close(ql, close_fd, *args, **kw):
    regreturn = -1
    if close_fd < 256 and ql.os.fd[close_fd] != 0:
        ql.os.fd[close_fd].close()
        ql.os.fd[close_fd] = 0
        regreturn = 0
    logging.info("close(%d) = %d" % (close_fd, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_pread64(ql, read_fd, read_buf, read_len, read_offt, *args, **kw):
    data = None
    if read_fd < 256 and ql.os.fd[read_fd] != 0:
        try:
            pos = ql.os.fd[read_fd].tell()
            ql.os.fd[read_fd].lseek(read_offt)
            data = ql.os.fd[read_fd].read(read_len)
            ql.os.fd[read_fd].lseek(pos)
            ql.mem.write(read_buf, data)
            regreturn = len(data)
        except:
            regreturn = -1
    else:
        regreturn = -1
    logging.info("pread(%d, 0x%x, 0x%x, 0x%x) = 0x%x" % (read_fd, read_buf, read_len, read_offt, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_read(ql, read_fd, read_buf, read_len, *args, **kw):
    data = None
    if read_fd < 256 and ql.os.fd[read_fd] != 0:
        try:
            data = ql.os.fd[read_fd].read(read_len)
            ql.mem.write(read_buf, data)
            regreturn = len(data)
        except:
            regreturn = -1
    else:
        regreturn = -1
    logging.info("read(%d, 0x%x, 0x%x) = %d" % (read_fd, read_buf, read_len, regreturn))

    if data:
        logging.debug("[+] read() CONTENT:")
        logging.debug("%s" % data)
    ql.os.definesyscall_return(regreturn)


def ql_syscall_write(ql, write_fd, write_buf, write_count, *args, **kw):
    regreturn = 0
    buf = None

    try:
        buf = ql.mem.read(write_buf, write_count)
        if buf:
            logging.debug("[+] write() CONTENT:")
            logging.debug("%s" % buf)

        if hasattr(ql.os.fd[write_fd], "write"):
            logging.info("write(%d,%x,%i) = %d" % (write_fd, write_buf, write_count, regreturn))
            ql.os.fd[write_fd].write(buf)
        else:
            logging.info("[!] write(%d,%x,%i) failed due to write_fd" % (write_fd, write_buf, write_count, regreturn))
        regreturn = write_count

    except:
        regreturn = -1
        logging.info("write(%d,%x,%i) = %d" % (write_fd, write_buf, write_count, regreturn))
        if ql.output in (QL_OUTPUT.DEBUG, QL_OUTPUT.DUMP):
            raise
    #if buf:
    #    logging.info(buf.decode(errors='ignore'))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_readlink(ql, path_name, path_buff, path_buffsize, *args, **kw):
    pathname = (ql.mem.read(path_name, 0x100).split(b'\x00'))[0]
    pathname = str(pathname, 'utf-8', errors="ignore")

    real_path = ql.os.transform_to_link_path(pathname)
    relative_path = ql.os.transform_to_relative_path(pathname)

    if os.path.exists(real_path) == False:
        regreturn = -1
    elif relative_path == '/proc/self/exe':
        FILEPATH = ql.path
        localpath = os.path.abspath(FILEPATH)
        localpath = bytes(localpath, 'utf-8') + b'\x00'
        ql.mem.write(path_buff, localpath)
        regreturn = (len(localpath)-1)
    else:
        regreturn = 0x0

    logging.info("readlink(%s, 0x%x, 0x%x) = %d" % (relative_path, path_buff, path_buffsize, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_getcwd(ql, path_buff, path_buffsize, *args, **kw):
    localpath = ql.os.transform_to_relative_path('./')
    localpath = bytes(localpath, 'utf-8') + b'\x00'
    ql.mem.write(path_buff, localpath)
    regreturn = (len(localpath))

    pathname = (ql.mem.read(path_buff, 0x100).split(b'\x00'))[0]
    pathname = str(pathname, 'utf-8', errors="ignore")

    logging.info("getcwd(%s, 0x%x) = %d" % (pathname, path_buffsize, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_chdir(ql, path_name, *args, **kw):
    regreturn = 0
    pathname = ql.mem.string(path_name)

    real_path = ql.os.transform_to_real_path(pathname)
    relative_path = ql.os.transform_to_relative_path(pathname)

    if os.path.exists(real_path) and os.path.isdir(real_path):
        if ql.os.thread_management != None:
            pass
        else:
            ql.os.current_path = relative_path
        logging.info("chdir(%s) = %d"% (relative_path, regreturn))
    else:
        regreturn = -1
        logging.info("chdir(%s) = %d : Not Found" % (relative_path, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_readlinkat(ql, readlinkat_dfd, readlinkat_path, readlinkat_buf, readlinkat_bufsiz, *args, **kw):
    pathname = (ql.mem.read(readlinkat_path, 0x100).split(b'\x00'))[0]
    pathname = str(pathname, 'utf-8', errors="ignore")

    real_path = ql.os.transform_to_link_path(pathname)
    relative_path = ql.os.transform_to_relative_path(pathname)

    if os.path.exists(real_path) == False:
        regreturn = -1
    elif relative_path == '/proc/self/exe':
        FILEPATH = ql.path
        localpath = os.path.abspath(FILEPATH)
        localpath = bytes(localpath, 'utf-8') + b'\x00'
        ql.mem.write(readlinkat_buf, localpath)
        regreturn = (len(localpath)-1)
    else:
        regreturn = 0x0

    logging.info("readlinkat(0x%x, 0x%x, 0x%x, 0x%x) = %d" % (readlinkat_dfd, readlinkat_path, readlinkat_buf, readlinkat_bufsiz, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_getpid(ql, *args, **kw):
    regreturn= 0x512
    logging.info("getpid() = %d" % (regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_getppid(ql, *args, **kw):
    regreturn= 0x1024
    logging.info("getpid() = %d" % (regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_vfork(ql, *args, **kw):
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
        logging.debug("[+] vfork(): is this a child process: %r" % (ql.os.child_processes))
        regreturn = 0
        if ql.os.thread_management != None:
            ql.os.thread_management.cur_thread.set_thread_log_file(ql.log_dir)
        else:
            if ql.log_split:
                _logger = ql.log_file_fd
                _logger = ql_setup_logging_file(ql.output, ql.log_file , _logger)
                _logger_name = str(len(logging.root.manager.loggerDict))
                _logger = ql_setup_logging_file(ql.output, '_'.join((ql.log_file, _logger_name)))
                ql.log_file_fd = _logger
    else:
        regreturn = pid

    if ql.os.thread_management != None:
        ql.emu_stop()

    logging.info("vfork() = %d" % regreturn)
    ql.os.definesyscall_return(regreturn)


def ql_syscall_setsid(ql, *args, **kw):
    regreturn = os.getpid()
    logging.info("setsid() = %d" % regreturn)
    ql.os.definesyscall_return(regreturn)


def ql_syscall_execve(ql, execve_pathname, execve_argv, execve_envp, *args, **kw):
    pathname = ql.mem.string(execve_pathname)
    real_path = ql.os.transform_to_real_path(pathname)
    relative_path = ql.os.transform_to_relative_path(pathname)

    word_size = 8 if (ql.archtype== QL_ARCH.ARM64) or (ql.archtype== QL_ARCH.X8664) else 4
    unpack = ql.unpack64 if (ql.archtype== QL_ARCH.ARM64) or (ql.archtype== QL_ARCH.X8664) else ql.unpack32

    argv = []
    if execve_argv != 0:
        while True:
            argv_addr = unpack(ql.mem.read(execve_argv, word_size))
            if argv_addr == 0:
                break
            argv.append(ql.mem.string(argv_addr))
            execve_argv += word_size

    env = {}
    if execve_envp != 0:
        while True:
            env_addr = unpack(ql.mem.read(execve_envp, word_size))
            if env_addr == 0:
                break
            env_str = ql.mem.string(env_addr)
            idx = env_str.index('=')
            key = env_str[ : idx]
            val = env_str[idx + 1 : ]
            env[key] = val
            execve_envp += word_size

    ql.emu_stop()
    
    logging.info("execve(%s, [%s], [%s])"% (pathname, ', '.join(argv), ', '.join([key + '=' + value for key, value in env.items()])))

    if ql.shellcoder:
        return

    ql.loader.argv      = argv
    ql.loader.env       = env
    ql._path             = real_path
    ql.mem.map_info     = []
    ql.clear_ql_hooks()
    
    ql._uc               = ql.arch.init_uc
    ql.os.load()
    ql.loader.run()
    ql.run()


def ql_syscall_dup(ql, dup_oldfd, *args, **kw):
    regreturn = -1
    if dup_oldfd in range(0, 256):
        if ql.os.fd[dup_oldfd] != 0:
            newfd = ql.os.fd[dup_oldfd].dup()
            for idx, val in enumerate(ql.os.fd):
                if val == 0:
                    ql.os.fd[idx] = newfd
                    regreturn = idx
                    break

    logging.info("dup(%d) = %d" % (dup_oldfd, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_dup2(ql, dup2_oldfd, dup2_newfd, *args, **kw):
    if 0 <= dup2_newfd < 256 and 0 <= dup2_oldfd < 256:
        if ql.os.fd[dup2_oldfd] != 0:
            ql.os.fd[dup2_newfd] = ql.os.fd[dup2_oldfd].dup()
            regreturn = dup2_newfd
        else:
            regreturn = -1
    else:
        regreturn = -1
    logging.info("dup2(%d, %d) = %d" % (dup2_oldfd, dup2_newfd, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_dup3(ql, dup3_oldfd, dup3_newfd, dup3_flags, null2, null3, null4):
    if 0 <= dup3_newfd < 256 and 0 <= dup3_oldfd < 256:
        if ql.os.fd[dup3_oldfd] != 0:
            ql.os.fd[dup3_newfd] = ql.os.fd[dup3_oldfd].dup()
            regreturn = dup3_newfd
        else:
            regreturn = -1
    else:
        regreturn = -1
    logging.info("dup3(%d, %d, %d) = %d" % (dup3_oldfd, dup3_newfd, dup3_flags, regreturn))
    ql.os.definesyscall_return(regreturn)

def ql_syscall_set_tid_address(ql, set_tid_address_tidptr, *args, **kw):
    if ql.os.thread_management == None:
        regreturn = os.getpid()
    else:
        ql.os.thread_management.cur_thread.set_clear_child_tid_addr(set_tid_address_tidptr)
        regreturn = ql.os.thread_management.cur_thread.id
    logging.info("set_tid_address(%x) = %d" % (set_tid_address_tidptr, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_pipe(ql, pipe_pipefd, *args, **kw):
    rd, wd = ql_pipe.open()

    idx1 = -1
    for i in range(256):
        if ql.os.fd[i] == 0:
            idx1 = i
            break
    if idx1 == -1:
        regreturn = -1
    else:
        idx2 = -1
        for i in range(256):
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
                ql.mem.write(pipe_pipefd, ql.pack32(idx1) + ql.pack32(idx2))
                regreturn = 0

    logging.info("pipe(%x, [%d, %d]) = %d" % (pipe_pipefd, idx1, idx2, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_nice(ql, nice_inc, *args, **kw):
    regreturn = 0
    logging.info("nice(%d) = %d" % (nice_inc, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_truncate(ql, path, length, *args, **kw):
    path = ql.mem.string(path)
    real_path = ql.os.transform_to_real_path(path)
    st_size = Stat(real_path).st_size

    try:
        if st_size >= length:
            os.truncate(real_path, length)

        else:
            padding = (length - st_size)
            with open(real_path, 'a+b') as fd:
                fd.write(b'\x00'*padding)

        regreturn = 0
    except:
        regreturn = -1

    logging.info('truncate(%s, 0x%x) = %d' % (path, length, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_ftruncate(ql, ftrunc_fd, ftrunc_length, *args, **kw):
    real_path = ql.os.fd[ftrunc_fd].name
    st_size = Stat(real_path).st_size

    try:
        if st_size >= ftrunc_length:
            os.truncate(real_path, ftrunc_length)

        else:
            padding = (ftrunc_length - st_size)
            with open(real_path, 'a+b') as fd:
                fd.write(b'\x00'*padding)

        regreturn = 0
    except:
        regreturn = -1

    logging.info('ftruncate(%d, 0x%x) = %d' % (ftrunc_fd, ftrunc_length, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_unlink(ql, unlink_pathname, *args, **kw):
    pathname = ql.mem.string(unlink_pathname)
    real_path = ql.os.transform_to_real_path(pathname)
    opened_fds = [getattr(ql.os.fd[i], 'name', None) for i in range(256) if ql.os.fd[i] != 0]
    path = pathlib.Path(real_path)

    if any((real_path not in opened_fds, path.is_block_device(), path.is_fifo(), path.is_socket(), path.is_symlink())):
        try:
            os.unlink(real_path)
            regreturn = 0
        except FileNotFoundError:
            logging.debug('[!] No such file or directory')
            regreturn = -1
        except:
            regreturn = -1
    else:
        regreturn = -1

    logging.info('unlink(%s) = %d' % (pathname, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_unlinkat(ql, dirfd, pathname, flag, *args, **kw):
    #FIXME dirfd(relative path) not implement.
    file_path = ql.mem.string(pathname)
    real_path = ql.os.transform_to_real_path(file_path)
    logging.info("unlinkat(%d, %s, 0%o)" % (dirfd, real_path, flag))
    try:
        os.unlink(real_path)
        regreturn = 0
    except FileNotFoundError:
        logging.debug("[!] No such file or directory")
        regreturn = -1
    except:
        regreturn = -1
    ql.os.definesyscall_return(regreturn)


def ql_syscall_getdents(ql, fd, dirp, count, *args, **kw):
    # TODO: not sure what is the meaning of d_off, should not be 0x0
    # but works for the example code from linux manual.
    def _type_mapping(ent):
        methods_constants_d = {'is_fifo': 0x1, 'is_char_device': 0x2, 'is_dir': 0x4, 'is_block_device': 0x6,
                                'is_file': 0x8, 'is_symlink': 0xa, 'is_socket': 0xc}
        ent_p = pathlib.Path(ent.path) if isinstance(ent, os.DirEntry) else ent

        for method, constant in methods_constants_d.items():
            if getattr(ent_p, method, None)():
                t = constant
                break
        else:
            t = 0x0 # DT_UNKNOWN

        return bytes([t])

    if ql.os.fd[fd].tell() == 0:
        n = ql.archbit // 8
        total_size = 0
        results = os.scandir(ql.os.fd[fd].name)
        _ent_count = 0

        for result in itertools.chain((pathlib.Path('.'), pathlib.Path('..')), results): # chain speical directories with the results
            d_ino = result.inode() if isinstance(result, os.DirEntry) else result.stat().st_ino
            d_off = 0x0
            d_name = (result.name if isinstance(result, os.DirEntry) else result._str).encode() + b'\x00'
            d_type = _type_mapping(result)
            d_reclen = len(d_name) + n*2 + 3

            ql.mem.write(dirp, ql.pack(d_ino))
            ql.mem.write(dirp+n, ql.pack(d_off))
            ql.mem.write(dirp+n*2, ql.pack16(d_reclen))
            ql.mem.write(dirp+n*2+2, d_name)
            ql.mem.write(dirp+n*2+2+len(d_name), d_type)

            dirp += d_reclen
            total_size += d_reclen
            _ent_count += 1

        regreturn = total_size
        ql.os.fd[fd].lseek(0, os.SEEK_END) # mark as end of file for dir_fd
    else:
        _ent_count = 0
        regreturn = 0

    logging.info("getdents(%d, 0x%x, 0x%x) = %d" % (fd, dirp, count, regreturn))
    logging.debug("[+] getdents(%d, /* %d entries */, 0x%x) = %d" % (fd, _ent_count, count, regreturn))
    ql.os.definesyscall_return(regreturn)

