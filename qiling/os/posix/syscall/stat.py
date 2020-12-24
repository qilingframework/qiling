#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import logging
from qiling.const import *
from qiling.os.linux.thread import *
from qiling.const import *
from qiling.os.posix.filestruct import *
from qiling.os.filestruct import *
from qiling.os.posix.const_mapping import *
from qiling.exception import *
from qiling.os.stat import *

def ql_syscall_chmod(ql, filename, mode, null1, null2, null3, null4):
    regreturn = 0
    filename = ql.mem.string(filename)
    logging.info("chmod(%s,%d) = %d" % (filename, mode, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_fstatat64(ql, fstatat64_fd, fstatat64_fname, fstatat64_buf, fstatat64_flag, *args, **kw):
    fstatat64_fname = ql.mem.string(fstatat64_fname)

    real_path = ql.os.transform_to_real_path(fstatat64_fname)
    relative_path = ql.os.transform_to_relative_path(fstatat64_fname)

    regreturn = -1
    if os.path.exists(real_path) == True:
        fstat64_info = Stat(real_path)

        # struct stat is : 80 addr is : 0x4000811bc8
        # buf.st_dev offest 0 8 0
        # buf.st_ino offest 8 8 0
        # buf.st_mode offest 10 4 0
        # buf.st_nlink offest 14 4 0
        # buf.st_uid offest 18 4 0
        # buf.st_gid offest 1c 4 0
        # buf.st_rdev offest 20 8 0
        # buf.st_size offest 30 8 274886889936
        # buf.st_blksize offest 38 4 8461328
        # buf.st_blocks offest 40 8 274877909532
        # buf.st_atime offest 48 8 274886368336
        # buf.st_mtime offest 58 8 274877909472
        # buf.st_ctime offest 68 8 274886368336
        # buf.__glibc_reserved offest 78 8
        fstat64_buf = ql.pack64(fstat64_info.st_dev)
        fstat64_buf += ql.pack64(fstat64_info.st_ino)
        fstat64_buf += ql.pack32(fstat64_info.st_mode)
        fstat64_buf += ql.pack32(fstat64_info.st_nlink)
        fstat64_buf += ql.pack32(1000)
        fstat64_buf += ql.pack32(1000)
        fstat64_buf += ql.pack64(fstat64_info.st_rdev)
        fstat64_buf += ql.pack64(0)
        fstat64_buf += ql.pack64(fstat64_info.st_size)
        fstat64_buf += ql.pack32(fstat64_info.st_blksize)
        fstat64_buf += ql.pack32(0)
        fstat64_buf += ql.pack64(fstat64_info.st_blocks)
        fstat64_buf += ql.pack64(int(fstat64_info.st_atime))
        fstat64_buf += ql.pack64(0)
        fstat64_buf += ql.pack64(int(fstat64_info.st_mtime))
        fstat64_buf += ql.pack64(0)
        fstat64_buf += ql.pack64(int(fstat64_info.st_ctime))
        fstat64_buf += ql.pack64(0)
        ql.mem.write(fstatat64_buf,fstat64_buf)
        regreturn = 0

    logging.info("fstatat64(0x%x, %s) = %d" % (fstatat64_fd, relative_path, regreturn))

    if regreturn == 0:
        logging.debug("[+] Directory Found: %s" % relative_path)
    else:
        logging.debug("[!] Directory Not Found: %s" % relative_path)

    ql.os.definesyscall_return(regreturn)


def ql_syscall_fstat64(ql, fstat64_fd, fstat64_add, *args, **kw):

    if ql.os.fd[fstat64_fd].fstat() == -1:
        regreturn = 0

    elif fstat64_fd < 256 and ql.os.fd[fstat64_fd] != 0:
        user_fileno = fstat64_fd
        fstat64_info = ql.os.fd[user_fileno].fstat()

        if ql.archtype== QL_ARCH.ARM64:
            # struct stat is : 80 addr is : 0x4000811bc8
            # buf.st_dev offest 0 8 0
            # buf.st_ino offest 8 8 0
            # buf.st_mode offest 10 4 0
            # buf.st_nlink offest 14 4 0
            # buf.st_uid offest 18 4 0
            # buf.st_gid offest 1c 4 0
            # buf.st_rdev offest 20 8 0
            # buf.st_size offest 30 8 274886889936
            # buf.st_blksize offest 38 4 8461328
            # buf.st_blocks offest 40 8 274877909532
            # buf.st_atime offest 48 8 274886368336
            # buf.st_mtime offest 58 8 274877909472
            # buf.st_ctime offest 68 8 274886368336
            # buf.__glibc_reserved offest 78 8
            fstat64_buf = ql.pack64(fstat64_info.st_dev)
            fstat64_buf += ql.pack64(fstat64_info.st_ino)
            fstat64_buf += ql.pack32(fstat64_info.st_mode)
            fstat64_buf += ql.pack32(fstat64_info.st_nlink)
            fstat64_buf += ql.pack32(ql.os.uid)
            fstat64_buf += ql.pack32(ql.os.gid)
            fstat64_buf += ql.pack64(fstat64_info.st_rdev)
            fstat64_buf += ql.pack64(0)
            fstat64_buf += ql.pack64(fstat64_info.st_size)
            fstat64_buf += ql.pack32(fstat64_info.st_blksize)
            fstat64_buf += ql.pack32(0)
            fstat64_buf += ql.pack64(fstat64_info.st_blocks)
            fstat64_buf += ql.pack64(int(fstat64_info.st_atime))
            fstat64_buf += ql.pack64(0)
            fstat64_buf += ql.pack64(int(fstat64_info.st_mtime))
            fstat64_buf += ql.pack64(0)
            fstat64_buf += ql.pack64(int(fstat64_info.st_ctime))
            fstat64_buf += ql.pack64(0)
        elif ql.archtype == QL_ARCH.MIPS:
            # struct stat is : a0 addr is : 0x7fffedc0
            # buf.st_dev offest 0 4 2049
            # buf.st_ino offest 10 8 2400362
            # buf.st_mode offest 18 4 16893
            # buf.st_nlink offest 1c 4 5
            # buf.st_uid offest 20 4 1000
            # buf.st_gid offest 24 4 1000
            # buf.st_rdev offest 28 4 0
            # buf.st_size offest 38 8 0
            # buf.st_blksize offest 58 4 4096
            # buf.st_blocks offest 60 8 136
            # buf.st_atime offest 40 4 1586616689
            # buf.st_mtime offest 48 4 1586616689
            # buf.st_ctime offest 50 4 1586616689
            if ql.platform == QL_OS.MACOS:
                fstat64_buf = ql.pack32s(fstat64_info.st_dev)
            else:
                fstat64_buf = ql.pack32(fstat64_info.st_dev)
            fstat64_buf += b'\x00' * 12
            fstat64_buf += ql.pack64(fstat64_info.st_ino)
            fstat64_buf += ql.pack32(fstat64_info.st_mode)
            fstat64_buf += ql.pack32(fstat64_info.st_nlink)
            fstat64_buf += ql.pack32(ql.os.uid)
            fstat64_buf += ql.pack32(ql.os.gid)
            fstat64_buf += ql.pack32(fstat64_info.st_rdev)
            fstat64_buf += b'\x00' * 12
            fstat64_buf += ql.pack64(fstat64_info.st_size)
            fstat64_buf += ql.pack64(int(fstat64_info.st_atime))
            fstat64_buf += ql.pack64(0)
            fstat64_buf += ql.pack64(int(fstat64_info.st_mtime))
            fstat64_buf += ql.pack64(0)
            fstat64_buf += ql.pack64(int(fstat64_info.st_ctime))
            fstat64_buf += ql.pack64(0)
            fstat64_buf += ql.pack32(fstat64_info.st_blksize)
            fstat64_buf += ql.pack32(0)
            fstat64_buf += ql.pack64(fstat64_info.st_blocks)        
        elif ql.archtype == QL_ARCH.ARM:
            # pack fstatinfo
            if ql.platform == QL_OS.MACOS:
                fstat64_buf = ql.pack64s(fstat64_info.st_dev)
            else:
                fstat64_buf = ql.pack64(fstat64_info.st_dev)
            fstat64_buf += ql.pack32(0)
            fstat64_buf += ql.pack32(fstat64_info.st_ino)
            fstat64_buf += ql.pack32(fstat64_info.st_mode)
            fstat64_buf += ql.pack32(fstat64_info.st_nlink)
            fstat64_buf += ql.pack32(fstat64_info.st_uid)
            fstat64_buf += ql.pack32(fstat64_info.st_gid)
            fstat64_buf += ql.pack64(fstat64_info.st_rdev) #?? fstat_info.st_rdev
            fstat64_buf += ql.pack64(0) 
            fstat64_buf += ql.pack64(fstat64_info.st_size)
            fstat64_buf += ql.pack64(fstat64_info.st_blksize) #?? fstat_info.st_blksize
            fstat64_buf += ql.pack64(fstat64_info.st_blocks) #?? fstat_info.st_blocks
            fstat64_buf += ql.pack64(int(fstat64_info.st_atime))
            fstat64_buf += ql.pack64(int(fstat64_info.st_mtime))
            fstat64_buf += ql.pack64(int(fstat64_info.st_ctime))
            fstat64_buf += ql.pack64(fstat64_info.st_ino)

        else:
            # pack fstatinfo
            if ql.platform == QL_OS.MACOS:
                fstat64_buf = ql.pack64s(fstat64_info.st_dev)
            else:
                fstat64_buf = ql.pack64(fstat64_info.st_dev)
            fstat64_buf += ql.pack64(0x0000000300c30000)
            fstat64_buf += ql.pack32(fstat64_info.st_mode)
            fstat64_buf += ql.pack32(fstat64_info.st_nlink)
            fstat64_buf += ql.pack32(fstat64_info.st_uid)
            fstat64_buf += ql.pack32(fstat64_info.st_gid)
            fstat64_buf += ql.pack64(0x0000000000008800) #?? fstat_info.st_rdev
            fstat64_buf += ql.pack32(0xffffd257)
            fstat64_buf += ql.pack64(fstat64_info.st_size)
            fstat64_buf += ql.pack32(0x00000400) #?? fstat_info.st_blksize
            fstat64_buf += ql.pack64(0x0000000000000000) #?? fstat_info.st_blocks
            fstat64_buf += ql.pack64(int(fstat64_info.st_atime))
            fstat64_buf += ql.pack64(int(fstat64_info.st_mtime))
            fstat64_buf += ql.pack64(int(fstat64_info.st_ctime))
            fstat64_buf += ql.pack64(fstat64_info.st_ino)

        ql.mem.write(fstat64_add, fstat64_buf)
        regreturn = 0
    else:
        regreturn = -1

    logging.info("fstat64(%d, 0x%x) = %d" % (fstat64_fd, fstat64_add, regreturn))
    if regreturn == 0:
        logging.debug("[+] fstat64 write completed")
    else:
        logging.debug("[!] fstat64 read/write fail")
    ql.os.definesyscall_return(regreturn)


def ql_syscall_fstat(ql, fstat_fd, fstat_add, *args, **kw):

    if fstat_fd < 256 and ql.os.fd[fstat_fd] != 0 and hasattr(ql.os.fd[fstat_fd], "fstat"):
        user_fileno = fstat_fd
        fstat_info = ql.os.fd[user_fileno].fstat()

        if ql.archtype== QL_ARCH.MIPS:
            # pack fstatinfo
            fstat_buf = ql.pack32(fstat_info.st_dev)
            fstat_buf += ql.pack32(0) * 3
            fstat_buf += ql.pack32(fstat_info.st_ino)
            fstat_buf += ql.pack32(fstat_info.st_mode)
            fstat_buf += ql.pack32(fstat_info.st_nlink)
            fstat_buf += ql.pack32(fstat_info.st_uid)
            fstat_buf += ql.pack32(fstat_info.st_gid)
            fstat_buf += ql.pack32(fstat_info.st_rdev)
            fstat_buf += ql.pack32(0) * 2
            fstat_buf += ql.pack32(fstat_info.st_size)
            fstat_buf += ql.pack32(0)
            fstat_buf += ql.pack32(int(fstat_info.st_atime))
            fstat_buf += ql.pack32(0)
            fstat_buf += ql.pack32(int(fstat_info.st_mtime))
            fstat_buf += ql.pack32(0)
            fstat_buf += ql.pack32(int(fstat_info.st_ctime))
            fstat_buf += ql.pack32(0)
            fstat_buf += ql.pack32(fstat_info.st_blksize)
            fstat_buf += ql.pack32(fstat_info.st_blocks)
            fstat_buf = fstat_buf.ljust(0x90, b'\x00')
        elif ql.archtype== QL_ARCH.X8664:
            if ql.platform == QL_OS.MACOS:
                fstat_buf = ql.pack64s(fstat_info.st_dev)
            else:
                fstat_buf = ql.pack64(fstat_info.st_dev)
            fstat_buf += ql.pack(fstat_info.st_ino)
            fstat_buf += ql.pack64(fstat_info.st_nlink)
            fstat_buf += ql.pack32(fstat_info.st_mode)
            fstat_buf += ql.pack32(fstat_info.st_uid)
            fstat_buf += ql.pack32(fstat_info.st_gid)
            fstat_buf += ql.pack32(0)
            fstat_buf += ql.pack64(fstat_info.st_rdev)
            fstat_buf += ql.pack64(fstat_info.st_size)
            fstat_buf += ql.pack64(fstat_info.st_blksize)
            fstat_buf += ql.pack64(fstat_info.st_blocks)
            fstat_buf += ql.pack64(int(fstat_info.st_atime))
            fstat_buf += ql.pack64(0)
            fstat_buf += ql.pack64(int(fstat_info.st_mtime))
            fstat_buf += ql.pack64(0)
            fstat_buf += ql.pack64(int(fstat_info.st_ctime))
            fstat_buf += ql.pack64(0)
        elif ql.archtype== QL_ARCH.ARM64:
            # struct stat is : 80 addr is : 0x4000811bc8
            # buf.st_dev offest 0 8 0
            # buf.st_ino offest 8 8 0
            # buf.st_mode offest 10 4 0
            # buf.st_nlink offest 14 4 0
            # buf.st_uid offest 18 4 0
            # buf.st_gid offest 1c 4 0
            # buf.st_rdev offest 20 8 0
            # buf.st_size offest 30 8 274886889936
            # buf.st_blksize offest 38 4 8461328
            # buf.st_blocks offest 40 8 274877909532
            # buf.st_atime offest 48 8 274886368336
            # buf.st_mtime offest 58 8 274877909472
            # buf.st_ctime offest 68 8 274886368336
            # buf.__glibc_reserved offest 78 8
            if ql.platform == QL_OS.MACOS:
                fstat_buf = ql.pack64s(fstat_info.st_dev)
            else:
                fstat_buf = ql.pack64(fstat_info.st_dev)
            fstat_buf += ql.pack64(fstat_info.st_ino)
            fstat_buf += ql.pack32(fstat_info.st_mode)
            fstat_buf += ql.pack32(fstat_info.st_nlink)
            fstat_buf += ql.pack32(ql.os.uid)
            fstat_buf += ql.pack32(ql.os.gid)
            fstat_buf += ql.pack64(fstat_info.st_rdev)
            fstat_buf += ql.pack64(0)
            fstat_buf += ql.pack64(fstat_info.st_size)
            fstat_buf += ql.pack32(fstat_info.st_blksize)
            fstat_buf += ql.pack32(0)
            fstat_buf += ql.pack64(fstat_info.st_blocks)
            fstat_buf += ql.pack64(int(fstat_info.st_atime))
            fstat_buf += ql.pack64(0)
            fstat_buf += ql.pack64(int(fstat_info.st_mtime))
            fstat_buf += ql.pack64(0)
            fstat_buf += ql.pack64(int(fstat_info.st_ctime))
            fstat_buf += ql.pack64(0)
        else:
            # pack fstatinfo
            fstat_buf = ql.pack32(fstat_info.st_dev)
            fstat_buf += ql.pack(fstat_info.st_ino)
            fstat_buf += ql.pack32(fstat_info.st_mode)
            fstat_buf += ql.pack32(fstat_info.st_nlink)
            fstat_buf += ql.pack32(fstat_info.st_uid)
            fstat_buf += ql.pack32(fstat_info.st_gid)
            fstat_buf += ql.pack32(fstat_info.st_rdev)
            fstat_buf += ql.pack32(fstat_info.st_size)
            fstat_buf += ql.pack32(fstat_info.st_blksize)
            fstat_buf += ql.pack32(fstat_info.st_blocks)
            fstat_buf += ql.pack32(int(fstat_info.st_atime))
            fstat_buf += ql.pack32(int(fstat_info.st_mtime))
            fstat_buf += ql.pack32(int(fstat_info.st_ctime))

        ql.mem.write(fstat_add, fstat_buf)
        regreturn = 0
    else:
        regreturn = -1

    logging.info("fstat(%d, 0x%x) = %d" % (fstat_fd, fstat_add, regreturn))
    if regreturn == 0:
        logging.debug("[+] fstat write completed")
    else:
        logging.debug("[!] fstat read/write fail")
    ql.os.definesyscall_return(regreturn)


# int stat64(const char *pathname, struct stat64 *buf);
def ql_syscall_stat64(ql, stat64_pathname, stat64_buf_ptr, *args, **kw):
    stat64_file = (ql.mem.string(stat64_pathname))

    real_path = ql.os.transform_to_real_path(stat64_file)
    relative_path = ql.os.transform_to_relative_path(stat64_file)
    if os.path.exists(real_path) == False:
        regreturn = -1
    else:
        stat64_info = Stat(real_path)

        if ql.archtype== QL_ARCH.MIPS:
            # packfstatinfo
            # name offset size
            # struct stat is : a0
            # buf.st_dev offest 0 4
            # buf.st_ino offest 10 8
            # buf.st_mode offest 18 4
            # buf.st_nlink offest 1c 4
            # buf.st_uid offest 20 4
            # buf.st_gid offest 24 4
            # buf.st_rdev offest 28 4
            # buf.st_size offest 38 8
            # buf.st_blksize offest 58 4
            # buf.st_blocks offest 60 8
            # buf.st_atime offest 40 4
            # buf.st_mtime offest 48 4
            # buf.st_ctime offest 50 4
            stat64_buf = ql.pack32(stat64_info.st_dev)
            stat64_buf += ql.pack32(0) * 3
            stat64_buf += ql.pack64(stat64_info.st_ino)
            stat64_buf += ql.pack32(stat64_info.st_mode)
            stat64_buf += ql.pack32(stat64_info.st_nlink)
            stat64_buf += ql.pack32(1000)
            stat64_buf += ql.pack32(1000)
            stat64_buf += ql.pack32(stat64_info.st_rdev)
            stat64_buf += ql.pack32(0) * 3
            stat64_buf += ql.pack64(stat64_info.st_size)
            stat64_buf += ql.pack64(int(stat64_info.st_atime))
            stat64_buf += ql.pack64(int(stat64_info.st_mtime))
            stat64_buf += ql.pack64(int(stat64_info.st_ctime))
            stat64_buf += ql.pack32(stat64_info.st_blksize)
            stat64_buf += ql.pack32(0)
            stat64_buf += ql.pack64(stat64_info.st_blocks)
        else:
            # packfstatinfo
            stat64_buf = ql.pack64(stat64_info.st_dev)
            stat64_buf += ql.pack64(0x0000000300c30000)
            stat64_buf += ql.pack32(stat64_info.st_mode)
            stat64_buf += ql.pack32(stat64_info.st_nlink)
            stat64_buf += ql.pack32(stat64_info.st_uid)
            stat64_buf += ql.pack32(stat64_info.st_gid)
            stat64_buf += ql.pack64(0x0000000000008800) #?? fstat_info.st_rdev
            stat64_buf += ql.pack32(0xffffd257)
            stat64_buf += ql.pack64(stat64_info.st_size)
            stat64_buf += ql.pack32(0x00000400) #?? fstat_info.st_blksize
            stat64_buf += ql.pack64(0x0000000000000000) #?? fstat_info.st_blocks
            stat64_buf += ql.pack64(int(stat64_info.st_atime))
            stat64_buf += ql.pack64(int(stat64_info.st_mtime))
            stat64_buf += ql.pack64(int(stat64_info.st_ctime))
            stat64_buf += ql.pack64(stat64_info.st_ino)

        ql.mem.write(stat64_buf_ptr, stat64_buf)
        regreturn = 0

    logging.info("stat64(%s, 0x%x) = %d" % (relative_path, stat64_buf_ptr, regreturn))
    if regreturn == 0:
        logging.debug("[+] stat64 write completed")
    else:
        logging.debug("[!] stat64 read/write fail")
    ql.os.definesyscall_return(regreturn)


# int stat(const char *path, struct stat *buf);
def ql_syscall_stat(ql, stat_path, stat_buf_ptr, *args, **kw):
    stat_file = (ql.mem.string(stat_path))

    real_path = ql.os.transform_to_real_path(stat_file)
    relative_path = ql.os.transform_to_relative_path(stat_file)

    if os.path.exists(real_path) == False:
        regreturn = -1
    else:
        stat_info = Stat(real_path)

        if ql.archtype== QL_ARCH.MIPS:
            # pack fstatinfo
            stat_buf = ql.pack32(stat_info.st_dev)
            stat_buf += ql.pack32(0) * 3
            stat_buf += ql.pack32(stat_info.st_ino)
            stat_buf += ql.pack32(stat_info.st_mode)
            stat_buf += ql.pack32(stat_info.st_nlink)
            stat_buf += ql.pack32(stat_info.st_uid)
            stat_buf += ql.pack32(stat_info.st_gid)
            stat_buf += ql.pack32(stat_info.st_rdev)
            stat_buf += ql.pack32(0) * 2
            stat_buf += ql.pack32(stat_info.st_size)
            stat_buf += ql.pack32(0)
            stat_buf += ql.pack32(int(stat_info.st_atime))
            stat_buf += ql.pack32(0)
            stat_buf += ql.pack32(int(stat_info.st_mtime))
            stat_buf += ql.pack32(0)
            stat_buf += ql.pack32(int(stat_info.st_ctime))
            stat_buf += ql.pack32(0)
            stat_buf += ql.pack32(stat_info.st_blksize)
            stat_buf += ql.pack32(stat_info.st_blocks)
            stat_buf = stat_buf.ljust(0x90, b'\x00')
        else:
            # pack statinfo
            stat_buf = ql.pack32(stat_info.st_mode)
            stat_buf += ql.pack32(stat_info.st_ino)
            stat_buf += ql.pack32(stat_info.st_dev)
            stat_buf += ql.pack32(stat_info.st_rdev)
            stat_buf += ql.pack32(stat_info.st_nlink)
            stat_buf += ql.pack32(stat_info.st_size)
            stat_buf += ql.pack32(stat_info.st_size)
            stat_buf += ql.pack32(stat_info.st_size)
            stat_buf += ql.pack32(int(stat_info.st_atime))
            stat_buf += ql.pack32(int(stat_info.st_mtime))
            stat_buf += ql.pack32(int(stat_info.st_ctime))
            stat_buf += ql.pack32(stat_info.st_blksize)
            stat_buf += ql.pack32(stat_info.st_blocks)

        regreturn = 0
        ql.mem.write(stat_buf_ptr, stat_buf)

    logging.info("stat(%s, 0x%x) = %d" % (relative_path, stat_buf_ptr, regreturn))
    if regreturn == 0:
        logging.debug("[+] stat() write completed")
    else:
        logging.debug("[!] stat() read/write fail")
    ql.os.definesyscall_return(regreturn)


def ql_syscall_lstat(ql, lstat_path, lstat_buf_ptr, *args, **kw):
    lstat_file = (ql.mem.string(lstat_path))

    real_path = ql.os.transform_to_real_path(lstat_file)
    relative_path = ql.os.transform_to_relative_path(lstat_file)

    if os.path.exists(real_path) == False:
        regreturn = -1
    else:
        lstat_info = Lstat(real_path)

        if ql.archtype== QL_ARCH.MIPS:
            # pack fstatinfo
            lstat_buf = ql.pack32(lstat_info.st_dev)
            lstat_buf += ql.pack32(0) * 3
            lstat_buf += ql.pack32(lstat_info.st_ino)
            lstat_buf += ql.pack32(lstat_info.st_mode)
            lstat_buf += ql.pack32(lstat_info.st_nlink)
            lstat_buf += ql.pack32(lstat_info.st_uid)
            lstat_buf += ql.pack32(lstat_info.st_gid)
            lstat_buf += ql.pack32(lstat_info.st_rdev)
            lstat_buf += ql.pack32(0) * 2
            lstat_buf += ql.pack32(lstat_info.st_size)
            lstat_buf += ql.pack32(0)
            lstat_buf += ql.pack32(int(lstat_info.st_atime))
            lstat_buf += ql.pack32(0)
            lstat_buf += ql.pack32(int(lstat_info.st_mtime))
            lstat_buf += ql.pack32(0)
            lstat_buf += ql.pack32(int(lstat_info.st_ctime))
            lstat_buf += ql.pack32(0)
            lstat_buf += ql.pack32(lstat_info.st_blksize)
            lstat_buf += ql.pack32(lstat_info.st_blocks)
            lstat_buf = lstat_buf.ljust(0x90, b'\x00')
        else:
            # pack statinfo
            lstat_buf = ql.pack32(lstat_info.st_mode)
            lstat_buf += ql.pack32(lstat_info.st_ino)
            lstat_buf += ql.pack32(lstat_info.st_dev)
            lstat_buf += ql.pack32(lstat_info.st_rdev)
            lstat_buf += ql.pack32(lstat_info.st_nlink)
            lstat_buf += ql.pack32(lstat_info.st_size)
            lstat_buf += ql.pack32(lstat_info.st_size)
            lstat_buf += ql.pack32(lstat_info.st_size)
            lstat_buf += ql.pack32(int(lstat_info.st_atime))
            lstat_buf += ql.pack32(int(lstat_info.st_mtime))
            lstat_buf += ql.pack32(int(lstat_info.st_ctime))
            lstat_buf += ql.pack32(lstat_info.st_blksize)
            lstat_buf += ql.pack32(lstat_info.st_blocks)

        regreturn = 0
        ql.mem.write(lstat_buf_ptr, lstat_buf)

    logging.info("lstat(%s, 0x%x) = %d" % (relative_path, lstat_buf_ptr, regreturn))
    if regreturn == 0:
        logging.debug("[+] lstat() write completed")
    else:
        logging.debug("[!] lstat() read/write fail")
    ql.os.definesyscall_return(regreturn)

def ql_syscall_mknodat(ql, dirfd, pathname, mode, dev, *args, **kw):
    # fix me. dirfd(relative path) not implement.
    file_path = ql.mem.string(pathname)
    real_path = ql.os.transform_to_real_path(file_path)
    logging.info("mknodat(%d, %s, 0%o, %d)" % (dirfd, real_path, mode, dev))
    try:
        os.mknod(real_path, mode, dev)
        regreturn = 0
    except:
        regreturn = -1
    ql.os.definesyscall_return(regreturn)


def ql_syscall_mkdir(ql, pathname, mode, *args, **kw):
    file_path = ql.mem.string(pathname)
    real_path = ql.os.transform_to_real_path(file_path)
    logging.info("mkdir(%s, 0%o)" % (real_path, mode))
    try:
        if not os.path.exists(real_path):
            os.mkdir(real_path, mode)
        regreturn = 0
    except:
        regreturn = -1
    ql.os.definesyscall_return(regreturn)


def ql_syscall_umask(ql, mode, *args, **kw):
    oldmask = os.umask(mode)
    logging.info("umask(0%o) return oldmask 0%o" % (mode, oldmask))
    regreturn = oldmask
    ql.os.definesyscall_return(regreturn)
