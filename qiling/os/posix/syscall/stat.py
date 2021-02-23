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
        # pack statinfo
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
        # pack statinfo
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
        stat64_buf = ql.pack64(info.st_dev)  # 8
        stat64_buf += ql.pack64(info.st_ino)  # 16
        stat64_buf += ql.pack32(info.st_mode)  # 20
        stat64_buf += ql.pack32(info.st_nlink)  # 24
        stat64_buf += ql.pack32(ql.os.uid)  # 28
        stat64_buf += ql.pack32(ql.os.gid)  # 32
        stat64_buf += ql.pack64(info.st_rdev)  # 40
        stat64_buf += ql.pack64(0)  # 48
        stat64_buf += ql.pack64(info.st_size)  # 56
        stat64_buf += ql.pack32(info.st_blksize)  # 60
        stat64_buf += ql.pack32(0)  # 64
        stat64_buf += ql.pack64(info.st_blocks)  # 72
        stat64_buf += ql.pack64(int(info.st_atime))  # 80
        stat64_buf += ql.pack64(0)  # 88
        stat64_buf += ql.pack64(int(info.st_mtime))  # 96
        stat64_buf += ql.pack64(0)  # 104
        stat64_buf += ql.pack64(int(info.st_ctime))  # 114
        stat64_buf += ql.pack64(0)  # 120
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

        # ---------------------------
        #   Previous implementation
        # ---------------------------
        #
        # if ql.platform == QL_OS.MACOS:
        #   stat64_buf = ql.pack32s(info.st_dev)
        # else:
        #   stat64_buf = ql.pack32(info.st_dev)
        # stat64_buf += b'\x00' * 12 
        # stat64_buf += ql.pack64(info.st_ino)
        # stat64_buf += ql.pack32(info.st_mode)
        # stat64_buf += ql.pack32(info.st_nlink)
        # stat64_buf += ql.pack32(ql.os.uid)
        # stat64_buf += ql.pack32(ql.os.gid)
        # stat64_buf += ql.pack32(info.st_rdev)
        # stat64_buf += b'\x00' * 12
        # stat64_buf += ql.pack64(info.st_size)
        # stat64_buf += ql.pack64(int(info.st_atime))
        # stat64_buf += ql.pack64(0)
        # stat64_buf += ql.pack64(int(info.st_mtime))
        # stat64_buf += ql.pack64(0)
        # stat64_buf += ql.pack64(int(info.st_ctime))
        # stat64_buf += ql.pack64(0)
        # stat64_buf += ql.pack32(info.st_blksize)
        # stat64_buf += ql.pack32(0)
        # stat64_buf += ql.pack64(info.st_blocks)
        # 

        """
             struct stat64 {
                 dev_t           st_dev;           /* ID of device containing file */
                 mode_t          st_mode;          /* Mode of file (see below) */
                 nlink_t         st_nlink;         /* Number of hard links */
                 ino64_t         st_ino;           /* File serial number */
                 uid_t           st_uid;           /* User ID of the file */
                 gid_t           st_gid;           /* Group ID of the file */
                 dev_t           st_rdev;          /* Device ID */
                 struct timespec st_atimespec;     /* time of last access */
                 struct timespec st_mtimespec;     /* time of last data modification */
                 struct timespec st_ctimespec;     /* time of last status change */
                 struct timespec st_birthtimespec; /* time of file creation(birth) */
                 off_t           st_size;          /* file size, in bytes */
                 blkcnt_t        st_blocks;        /* blocks allocated for file */
                 blksize_t       st_blksize;       /* optimal blocksize for I/O */
                 uint32_t        st_flags;         /* user defined flags for file */
                 uint32_t        st_gen;           /* file generation number */
                 int32_t         st_lspare;        /* RESERVED: DO NOT USE! */
                 int64_t         st_qspare[2];     /* RESERVED: DO NOT USE! */
              }  

              struct timespec {
                 time_t          tv_sec;           /* seconds */
                 long            tv_nsec;          /* nanoseconds */
              }
        """

        ql.log.debug("[🥓] (syscall) inside the create_stat64_struct func")

        if ql.platform == QL_OS.MACOS:
            stat64_buf = ql.pack32s(info.st_dev)
        else:
            stat64_buf = ql.pack32(info.st_dev)

        stat64_buf += ql.pack32(info.st_mode)
        stat64_buf += ql.pack32(info.st_nlink)
        stat64_buf += ql.pack64(info.st_ino)
        stat64_buf += ql.pack32(ql.os.uid)
        stat64_buf += ql.pack32(ql.os.gid)

        if ql.platform == QL_OS.MACOS:
            stat64_buf += ql.pack32s(info.st_rdev)
        else:
            stat64_buf += ql.pack32(info.st_rdev)

        # struct timespec st_atimespec {
        stat64_buf += ql.pack64(int(info.st_atime))
        stat64_buf += ql.pack32(0)
        # }

        # struct timespec st_mtimespec {
        stat64_buf += ql.pack64(int(info.st_mtime))
        stat64_buf += ql.pack32(0)
        # }

        # struct timespec st_ctimespec {
        stat64_buf += ql.pack64(int(info.st_ctime))
        stat64_buf += ql.pack32(0)
        # }

        # struct timespec st_birthtimespec {
        stat64_buf += ql.pack64(int(info.st_atime) - 3600) # last access - 1 hr
        stat64_buf += ql.pack32(0)
        # }

        stat64_buf += ql.pack64(info.st_size)
        stat64_buf += ql.pack64(info.st_blocks)
        stat64_buf += ql.pack32(info.st_blksize)
        # stat64_buf += ql.pack32(0xffffffff) # st_flags
        # stat64_buf += ql.pack32(0xdeadbeef) # st_gen

        # Reserved
        # ---------
        # stat64_buf += ql.pack32s(0) # st_lspare
        # stat64_buf += ql.pack64s(0) # st_qspare[2]
        #
    elif ql.archtype == QL_ARCH.ARM:
        # pack statinfo
        if ql.platform == QL_OS.MACOS:
            stat64_buf = ql.pack64s(info.st_dev)
        else:
            stat64_buf = ql.pack64(info.st_dev)
        stat64_buf += ql.pack32(0)
        stat64_buf += ql.pack32(info.st_ino)
        stat64_buf += ql.pack32(info.st_mode)
        stat64_buf += ql.pack32(info.st_nlink)
        stat64_buf += ql.pack32(info.st_uid)
        stat64_buf += ql.pack32(info.st_gid)
        stat64_buf += ql.pack64(info.st_rdev)  # ?? stat_info.st_rdev
        stat64_buf += ql.pack64(0)
        stat64_buf += ql.pack64(info.st_size)
        stat64_buf += ql.pack64(info.st_blksize)  # ?? stat_info.st_blksize
        stat64_buf += ql.pack64(info.st_blocks)  # ?? stat_info.st_blocks
        stat64_buf += ql.pack64(int(info.st_atime))
        stat64_buf += ql.pack64(int(info.st_mtime))
        stat64_buf += ql.pack64(int(info.st_ctime))
        stat64_buf += ql.pack64(info.st_ino)
    elif ql.ostype == QL_OS.MACOS:
        stat64_buf = ql.pack32(info.st_dev)              # st_dev            32byte
        stat64_buf += ql.pack32(info.st_mode)            # st_mode           16(32)byte
        stat64_buf += ql.pack32(info.st_nlink)           # st_nlink          16(32)byte
        stat64_buf += ql.pack64(info.st_ino)             # st_ino            64 byte
        stat64_buf += ql.pack32(0x0)                            # st_uid            32 byte
        stat64_buf += ql.pack32(0x0)                            # st_gid            32 byte
        stat64_buf += ql.pack32(0x0)                            # st_rdev           32 byte
        stat64_buf += ql.pack64(int(info.st_atime))      # st_atime          64 byte
        stat64_buf += ql.pack64(0x0)                            # st_atimensec      64 byte
        stat64_buf += ql.pack64(int(info.st_mtime))      # st_mtime          64 byte
        stat64_buf += ql.pack64(0x0)                            # st_mtimensec      64 byte
        stat64_buf += ql.pack64(int(info.st_ctime))      # st_ctime          64 byte
        stat64_buf += ql.pack64(0x0)                            # st_ctimensec      64 byte
        if ql.platform == QL_OS.MACOS:
            stat64_buf += ql.pack64(int(info.st_birthtime))  # st_birthtime      64 byte
        else:
            stat64_buf += ql.pack64(int(info.st_ctime))  # st_birthtime      64 byte
        stat64_buf += ql.pack64(0x0)                            # st_birthtimensec  64 byte
        stat64_buf += ql.pack64(info.st_size)            # st_size           64 byte
        stat64_buf += ql.pack64(info.st_blocks)          # st_blocks         64 byte
        stat64_buf += ql.pack32(info.st_blksize)         # st_blksize        32 byte
        if ql.platform == QL_OS.MACOS:
            stat64_buf += ql.pack32(info.st_flags)       # st_flags          32 byte
        else:    
            stat64_buf += ql.pack32(0x0)          
        if ql.platform == QL_OS.MACOS:
            stat64_buf += ql.pack32(info.st_gen)         # st_gen            32 byte
        else:    
            stat64_buf += ql.pack32(0x0)
        stat64_buf += ql.pack32(0x0)                            # st_lspare         32 byte
        stat64_buf += ql.pack64(0x0)                            # st_qspare         64 byte
    else:
        # pack statinfo
        if ql.platform == QL_OS.MACOS:
            stat64_buf = ql.pack64s(info.st_dev)
        else:
            stat64_buf = ql.pack64(info.st_dev)
        stat64_buf += ql.pack64(0x0000000300c30000)
        stat64_buf += ql.pack32(info.st_mode)
        stat64_buf += ql.pack32(info.st_nlink)
        stat64_buf += ql.pack32(info.st_uid)
        stat64_buf += ql.pack32(info.st_gid)
        stat64_buf += ql.pack64(0x0000000000008800)  # ?? stat_info.st_rdev
        stat64_buf += ql.pack32(0xffffd257)
        stat64_buf += ql.pack64(info.st_size)
        stat64_buf += ql.pack32(0x00000400)  # ?? stat_info.st_blksize
        stat64_buf += ql.pack64(0x0000000000000000)
        stat64_buf += ql.pack64(int(info.st_atime))
        stat64_buf += ql.pack64(int(info.st_mtime))
        stat64_buf += ql.pack64(int(info.st_ctime))
        stat64_buf += ql.pack64(info.st_ino)
    return stat64_buf


def statFamily(ql, path, ptr, name, stat_func, struct_func):
    file = (ql.mem.string(path))
    real_path = ql.os.transform_to_real_path(file)
    regreturn = 0
    try:
        ql.log.debug(f'[🥓] (syscall) real_path: {real_path}')
        info = stat_func(real_path)
    except OSError as e:
        ql.log.debug(f'{name}("{file}", {hex(ptr)}) read/write fail')
        return -e.errno
    else:
        buf = struct_func(ql, info)
        ql.mem.write(ptr, buf)
        ql.log.debug(f'[🥓] (syscall) ptr: {hex(ptr)}')
        ql.log.debug(f'[🥓] (syscall) buf: {buf}')
        ql.log.debug(f'{name}("{file}", {hex(ptr)}) write completed')
        ql.log.debug(f'[🥓] (syscall) ¯\_(ツ)_/¯')
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
    ql.log.debug(f"[🥓] (syscall) inside ql_syscall_stat64")
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
