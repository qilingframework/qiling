#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


from qiling.const import *
from qiling.os.linux.thread import *
from qiling.const import *
from qiling.os.posix.filestruct import *
from qiling.os.filestruct import *
from qiling.os.posix.const_mapping import *
from qiling.exception import *
from qiling.os.posix.stat import *


def create_stat_struct(ql, info):
    if ql.archtype == QL_ARCH.MIPS:
        # pack fstatinfo
        stat_buf = ql.pack32(info.st_dev)
        stat_buf += ql.pack32(0) * 3
        stat_buf += ql.pack32(info.st_ino)
        stat_buf += ql.pack32(info.st_mode)
        stat_buf += ql.pack32(info.st_nlink)
        stat_buf += ql.pack32(info.st_uid)
        stat_buf += ql.pack32(info.st_gid)
        stat_buf += ql.pack32(info.st_rdev)
        stat_buf += ql.pack32(0) * 2
        stat_buf += ql.pack32(info.st_size)
        stat_buf += ql.pack32(0)
        stat_buf += ql.pack32(int(info.st_atime))
        stat_buf += ql.pack32(0)
        stat_buf += ql.pack32(int(info.st_mtime))
        stat_buf += ql.pack32(0)
        stat_buf += ql.pack32(int(info.st_ctime))
        stat_buf += ql.pack32(0)
        stat_buf += ql.pack32(info.st_blksize)
        stat_buf += ql.pack32(info.st_blocks)
        stat_buf = stat_buf.ljust(0x90, b'\x00')
    elif ql.archtype == QL_ARCH.X8664:
        if ql.platform == QL_OS.MACOS:
            stat_buf = ql.pack64s(info.st_dev)
        else:
            stat_buf = ql.pack64(info.st_dev)
        stat_buf += ql.pack(info.st_ino)
        stat_buf += ql.pack64(info.st_nlink)
        stat_buf += ql.pack32(info.st_mode)
        stat_buf += ql.pack32(info.st_uid)
        stat_buf += ql.pack32(info.st_gid)
        stat_buf += ql.pack32(0)
        stat_buf += ql.pack64(info.st_rdev)
        stat_buf += ql.pack64(info.st_size)
        stat_buf += ql.pack64(info.st_blksize)
        stat_buf += ql.pack64(info.st_blocks)
        stat_buf += ql.pack64(int(info.st_atime))
        stat_buf += ql.pack64(0)
        stat_buf += ql.pack64(int(info.st_mtime))
        stat_buf += ql.pack64(0)
        stat_buf += ql.pack64(int(info.st_ctime))
        stat_buf += ql.pack64(0)
    elif ql.archtype == QL_ARCH.ARM64:
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
            stat_buf = ql.pack64s(info.st_dev)
        else:
            stat_buf = ql.pack64(info.st_dev)
        stat_buf += ql.pack64(info.st_ino)
        stat_buf += ql.pack32(info.st_mode)
        stat_buf += ql.pack32(info.st_nlink)
        stat_buf += ql.pack32(ql.os.uid)
        stat_buf += ql.pack32(ql.os.gid)
        stat_buf += ql.pack64(info.st_rdev)
        stat_buf += ql.pack64(0)
        stat_buf += ql.pack64(info.st_size)
        stat_buf += ql.pack32(info.st_blksize)
        stat_buf += ql.pack32(0)
        stat_buf += ql.pack64(info.st_blocks)
        stat_buf += ql.pack64(int(info.st_atime))
        stat_buf += ql.pack64(0)
        stat_buf += ql.pack64(int(info.st_mtime))
        stat_buf += ql.pack64(0)
        stat_buf += ql.pack64(int(info.st_ctime))
        stat_buf += ql.pack64(0)
    else:
        # pack fstatinfo
        stat_buf = ql.pack32(info.st_dev)
        stat_buf += ql.pack(info.st_ino)
        stat_buf += ql.pack32(info.st_mode)
        stat_buf += ql.pack32(info.st_nlink)
        stat_buf += ql.pack32(info.st_uid)
        stat_buf += ql.pack32(info.st_gid)
        stat_buf += ql.pack32(info.st_rdev)
        stat_buf += ql.pack32(info.st_size)
        stat_buf += ql.pack32(info.st_blksize)
        stat_buf += ql.pack32(info.st_blocks)
        stat_buf += ql.pack32(int(info.st_atime))
        stat_buf += ql.pack32(int(info.st_mtime))
        stat_buf += ql.pack32(int(info.st_ctime))
    return stat_buf


def create_stat64_struct(ql, info):
    if ql.archtype == QL_ARCH.ARM64:
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
        fstat64_buf = ql.pack64(info.st_dev)  # 8
        fstat64_buf += ql.pack64(info.st_ino)  # 16
        fstat64_buf += ql.pack32(info.st_mode)  # 20
        fstat64_buf += ql.pack32(info.st_nlink)  # 24
        fstat64_buf += ql.pack32(ql.os.uid)  # 28
        fstat64_buf += ql.pack32(ql.os.gid)  # 32
        fstat64_buf += ql.pack64(info.st_rdev)  # 40
        fstat64_buf += ql.pack64(0)  # 48
        fstat64_buf += ql.pack64(info.st_size)  # 56
        fstat64_buf += ql.pack32(info.st_blksize)  # 60
        fstat64_buf += ql.pack32(0)  # 64
        fstat64_buf += ql.pack64(info.st_blocks)  # 72
        fstat64_buf += ql.pack64(int(info.st_atime))  # 80
        fstat64_buf += ql.pack64(0)  # 88
        fstat64_buf += ql.pack64(int(info.st_mtime))  # 96
        fstat64_buf += ql.pack64(0)  # 104
        fstat64_buf += ql.pack64(int(info.st_ctime))  # 114
        fstat64_buf += ql.pack64(0)  # 120
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
            fstat64_buf = ql.pack32s(info.st_dev)
        else:
            fstat64_buf = ql.pack32(info.st_dev)  # 4
        fstat64_buf += b'\x00' * 12  # 16
        fstat64_buf += ql.pack64(info.st_ino)  # 24
        fstat64_buf += ql.pack32(info.st_mode)
        fstat64_buf += ql.pack32(info.st_nlink)
        fstat64_buf += ql.pack32(ql.os.uid)
        fstat64_buf += ql.pack32(ql.os.gid)
        fstat64_buf += ql.pack32(info.st_rdev)
        fstat64_buf += b'\x00' * 12
        fstat64_buf += ql.pack64(info.st_size)
        fstat64_buf += ql.pack64(int(info.st_atime))
        fstat64_buf += ql.pack64(0)
        fstat64_buf += ql.pack64(int(info.st_mtime))
        fstat64_buf += ql.pack64(0)
        fstat64_buf += ql.pack64(int(info.st_ctime))
        fstat64_buf += ql.pack64(0)
        fstat64_buf += ql.pack32(info.st_blksize)
        fstat64_buf += ql.pack32(0)
        fstat64_buf += ql.pack64(info.st_blocks)
    elif ql.archtype == QL_ARCH.ARM:
        # pack fstatinfo
        if ql.platform == QL_OS.MACOS:
            fstat64_buf = ql.pack64s(info.st_dev)
        else:
            fstat64_buf = ql.pack64(info.st_dev)
        fstat64_buf += ql.pack32(0)
        fstat64_buf += ql.pack32(info.st_ino)
        fstat64_buf += ql.pack32(info.st_mode)
        fstat64_buf += ql.pack32(info.st_nlink)
        fstat64_buf += ql.pack32(info.st_uid)
        fstat64_buf += ql.pack32(info.st_gid)
        fstat64_buf += ql.pack64(info.st_rdev)  # ?? fstat_info.st_rdev
        fstat64_buf += ql.pack64(0)
        fstat64_buf += ql.pack64(info.st_size)
        fstat64_buf += ql.pack64(info.st_blksize)  # ?? fstat_info.st_blksize
        fstat64_buf += ql.pack64(info.st_blocks)  # ?? fstat_info.st_blocks
        fstat64_buf += ql.pack64(int(info.st_atime))
        fstat64_buf += ql.pack64(int(info.st_mtime))
        fstat64_buf += ql.pack64(int(info.st_ctime))
        fstat64_buf += ql.pack64(info.st_ino)
    elif ql.ostype == QL_OS.MACOS:
        fstat64_buf = ql.pack32(0x0)              # st_dev            32byte
        fstat64_buf += ql.pack32(info.st_mode)            # st_mode           16(32)byte
        fstat64_buf += ql.pack32(info.st_nlink)           # st_nlink          16(32)byte
        fstat64_buf += ql.pack64(info.st_ino)             # st_ino            64 byte
        fstat64_buf += ql.pack32(0x0)                            # st_uid            32 byte
        fstat64_buf += ql.pack32(0x0)                            # st_gid            32 byte
        fstat64_buf += ql.pack32(0x0)                            # st_rdev           32 byte
        fstat64_buf += ql.pack64(int(info.st_atime))      # st_atime          64 byte
        fstat64_buf += ql.pack64(0x0)                            # st_atimensec      64 byte
        fstat64_buf += ql.pack64(int(info.st_mtime))      # st_mtime          64 byte
        fstat64_buf += ql.pack64(0x0)                            # st_mtimensec      64 byte
        fstat64_buf += ql.pack64(int(info.st_ctime))      # st_ctime          64 byte
        fstat64_buf += ql.pack64(0x0)                            # st_ctimensec      64 byte
        if ql.platform == QL_OS.MACOS:
            fstat64_buf += ql.pack64(int(info.st_birthtime))  # st_birthtime      64 byte
        else:
            fstat64_buf += ql.pack64(int(info.st_ctime))  # st_birthtime      64 byte
        fstat64_buf += ql.pack64(0x0)                            # st_birthtimensec  64 byte
        fstat64_buf += ql.pack64(info.st_size)            # st_size           64 byte
        fstat64_buf += ql.pack64(info.st_blocks)          # st_blocks         64 byte
        fstat64_buf += ql.pack32(info.st_blksize)         # st_blksize        32 byte
        if ql.platform == QL_OS.MACOS:
            fstat64_buf += ql.pack32(info.st_flags)       # st_flags          32 byte
        else:    
            fstat64_buf += ql.pack32(0x0)          
        if ql.platform == QL_OS.MACOS:
            fstat64_buf += ql.pack32(info.st_gen)         # st_gen            32 byte
        else:    
            fstat64_buf += ql.pack32(0x0)
        fstat64_buf += ql.pack32(0x0)                            # st_lspare         32 byte
        fstat64_buf += ql.pack64(0x0)                            # st_qspare         64 byte
    else:
        # pack fstatinfo
        if ql.platform == QL_OS.MACOS:
            fstat64_buf = ql.pack64s(info.st_dev)
        else:
            fstat64_buf = ql.pack64(info.st_dev)
        fstat64_buf += ql.pack64(0x0000000300c30000)
        fstat64_buf += ql.pack32(info.st_mode)
        fstat64_buf += ql.pack32(info.st_nlink)
        fstat64_buf += ql.pack32(info.st_uid)
        fstat64_buf += ql.pack32(info.st_gid)
        fstat64_buf += ql.pack64(0x0000000000008800)  # ?? fstat_info.st_rdev
        fstat64_buf += ql.pack32(0xffffd257)
        fstat64_buf += ql.pack64(info.st_size)
        fstat64_buf += ql.pack32(0x00000400)  # ?? fstat_info.st_blksize
        fstat64_buf += ql.pack64(0x0000000000000000)  # ?? fstat_info.st_blocks
        fstat64_buf += ql.pack64(int(info.st_atime))
        fstat64_buf += ql.pack64(int(info.st_mtime))
        fstat64_buf += ql.pack64(int(info.st_ctime))
        fstat64_buf += ql.pack64(info.st_ino)
    return fstat64_buf


def statFamily(ql, path, ptr, name, stat_func, struct_func):
    file = (ql.mem.string(path))
    real_path = ql.os.transform_to_real_path(file)
    regreturn = 0
    try:
        info = stat_func(real_path)
    except OSError as e:
        ql.log.debug(f'{name}("{file}", {hex(ptr)}) read/write fail')
        return -e.errno
    else:
        buf = struct_func(ql, info)
        ql.mem.write(ptr, buf)
        ql.log.debug(f'{name}("{file}", {hex(ptr)}) write completed')
        return regreturn


def ql_syscall_chmod(ql, filename, mode, null1, null2, null3, null4):
    regreturn = 0
    filename = ql.mem.string(filename)
    ql.log.debug("chmod(%s,%d) = %d" % (filename, mode, regreturn))
    return regreturn


def ql_syscall_fstatat64(ql, fstatat64_dirfd, fstatat64_path, fstatat64_buf_ptr, fstatat64_flag, *args, **kw):
    # FIXME: dirfd(relative path) not implement.
    fstatat64_path = ql.mem.string(fstatat64_path)

    real_path = ql.os.transform_to_real_path(fstatat64_path)
    relative_path = ql.os.transform_to_relative_path(fstatat64_path)

    regreturn = -1
    if os.path.exists(real_path) == True:
        fstatat64_info = Stat(real_path)
        fstatat64_buf = create_stat64_struct(ql, fstatat64_info)
        ql.mem.write(fstatat64_buf_ptr, fstatat64_buf)
        regreturn = 0

    if regreturn == 0:
        ql.log.debug("Directory Found: %s" % relative_path)
    else:
        ql.log.debug("Directory Not Found: %s" % relative_path)

    return regreturn

def ql_syscall_newfstatat(ql, newfstatat_dirfd, newfstatat_path, newfstatat_buf_ptr, newfstatat_flag, *args, **kw):
    # FIXME: dirfd(relative path) not implement.
    newfstatat_path = ql.mem.string(newfstatat_path)

    real_path = ql.os.transform_to_real_path(newfstatat_path)
    relative_path = ql.os.transform_to_relative_path(newfstatat_path)

    regreturn = -1
    if os.path.exists(real_path) == True:
        newfstatat_info = Stat(real_path)
        newfstatat_buf = create_stat_struct(ql, newfstatat_info)
        ql.mem.write(newfstatat_buf_ptr, newfstatat_buf)
        regreturn = 0

    if regreturn == 0:
        ql.log.debug("Directory Found: %s" % relative_path)
    else:
        ql.log.debug("Directory Not Found: %s" % relative_path)

    return regreturn

def ql_syscall_fstat64(ql, fstat64_fd, fstat64_buf_ptr, *args, **kw):
    if ql.os.fd[fstat64_fd].fstat() == -1:
        regreturn = 0

    elif fstat64_fd < 256 and ql.os.fd[fstat64_fd] != 0:
        user_fileno = fstat64_fd
        fstat64_info = ql.os.fd[user_fileno].fstat()
        fstat64_buf = create_stat64_struct(ql, fstat64_info)
        ql.mem.write(fstat64_buf_ptr, fstat64_buf)
        regreturn = 0
    else:
        regreturn = -1

    if regreturn == 0:
        ql.log.debug("fstat64 write completed")
    else:
        ql.log.debug("fstat64 read/write fail")
    return regreturn


def ql_syscall_fstat(ql, fstat_fd, fstat_buf_ptr, *args, **kw):
    if fstat_fd < 256 and ql.os.fd[fstat_fd] != 0 and hasattr(ql.os.fd[fstat_fd], "fstat"):
        user_fileno = fstat_fd
        fstat_info = ql.os.fd[user_fileno].fstat()
        fstat_buf = create_stat_struct(ql, fstat_info)
        ql.mem.write(fstat_buf_ptr, fstat_buf)
        regreturn = 0
    else:
        regreturn = -1

    if regreturn == 0:
        ql.log.debug("fstat write completed")
    else:
        ql.log.debug("fstat read/write fail")
    return regreturn


# int stat(const char *path, struct stat *buf);
def ql_syscall_stat(ql, stat_path, stat_buf_ptr, *args, **kw):
    return statFamily(ql, stat_path, stat_buf_ptr, "stat", Stat, create_stat_struct)


# int stat64(const char *path, struct stat64 *buf);
def ql_syscall_stat64(ql, stat64_path, stat64_buf_ptr, *args, **kw):
    return statFamily(ql, stat64_path, stat64_buf_ptr, "stat64", Stat, create_stat64_struct)


def ql_syscall_lstat(ql, lstat_path, lstat_buf_ptr, *args, **kw):
    return statFamily(ql, lstat_path, lstat_buf_ptr, "lstat", Lstat, create_stat_struct)


def ql_syscall_lstat64(ql, lstat64_path, lstat64_buf_ptr, *args, **kw):
    return statFamily(ql, lstat64_path, lstat64_buf_ptr, "lstat64", Lstat, create_stat64_struct)


def ql_syscall_mknodat(ql, dirfd, pathname, mode, dev, *args, **kw):
    # FIXME: dirfd(relative path) not implement.
    file_path = ql.mem.string(pathname)
    real_path = ql.os.transform_to_real_path(file_path)
    ql.log.debug("mknodat(%d, %s, 0%o, %d)" % (dirfd, real_path, mode, dev))
    try:
        os.mknod(real_path, mode, dev)
        regreturn = 0
    except:
        regreturn = -1
    return regreturn


def ql_syscall_mkdir(ql, pathname, mode, *args, **kw):
    file_path = ql.mem.string(pathname)
    real_path = ql.os.transform_to_real_path(file_path)
    ql.log.debug("mkdir(%s, 0%o)" % (real_path, mode))
    try:
        if not os.path.exists(real_path):
            os.mkdir(real_path, mode)
        regreturn = 0
    except:
        regreturn = -1
    return regreturn


def ql_syscall_fstatfs(ql, fd, buf, *args, **kw):
    data = b"0" * (12*8)  # for now, just return 0s
    regreturn = None
    try:
        ql.mem.write(buf, data)
        regreturn = 0
    except:
        regreturn = -1

    ql.log.info("fstatfs(0x%x, 0x%x) = %d" % (fd, buf, regreturn))

    if data:
        ql.log.debug("fstatfs() CONTENT:")
        ql.log.debug(str(data))
    return regreturn


def ql_syscall_umask(ql, mode, *args, **kw):
    oldmask = os.umask(mode)
    ql.log.debug("umask(0%o) return oldmask 0%o" % (mode, oldmask))
    regreturn = oldmask
    return regreturn
