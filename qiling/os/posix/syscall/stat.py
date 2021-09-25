#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os
import ctypes
from typing import Callable

from qiling import Qiling
from qiling.const import QL_OS, QL_ARCH, QL_ENDIAN
from qiling.os.posix.const import NR_OPEN, EBADF
from qiling.os.posix.stat import Stat, Lstat

# Caveat: Never use types like ctypes.c_long whose size differs across platforms.

# /sys/sys/stat.h
# struct stat {
# 	dev_t     st_dev;		/* inode's device */                        uint64_t
# 	ino_t	  st_ino;		/* inode's number */                        uint64_t
# 	nlink_t	  st_nlink;		/* number of hard links */                  uint64_t
# 	mode_t	  st_mode;		/* inode protection mode */                 uint16_t
# 	__int16_t st_padding0;                                              int16_t
# 	uid_t	  st_uid;		/* user ID of the file's owner */           uint32_t
# 	gid_t	  st_gid;		/* group ID of the file's group */          uint32_t
# 	__int32_t st_padding1;                                              int32_t
# 	dev_t     st_rdev;		/* device type */                           uint64_t
# #ifdef	__STAT_TIME_T_EXT
# 	__int32_t st_atim_ext;
# #endif
# 	struct	timespec st_atim;	/* time of last access */               uint64_t * 2      
# #ifdef	__STAT_TIME_T_EXT
# 	__int32_t st_mtim_ext;
# #endif
# 	struct	timespec st_mtim;	/* time of last data modification */    uint64_t * 2
# #ifdef	__STAT_TIME_T_EXT
# 	__int32_t st_ctim_ext;
# #endif
# 	struct	timespec st_ctim;	/* time of last file status change */   uint64_t * 2
# #ifdef	__STAT_TIME_T_EXT
# 	__int32_t st_btim_ext;
# #endif
# 	struct	timespec st_birthtim;	/* time of file creation */         uint64_t * 2
# 	off_t	  st_size;		/* file size, in bytes */                   int64_t
# 	blkcnt_t st_blocks;		/* blocks allocated for file */             int64_t
# 	blksize_t st_blksize;		/* optimal blocksize for I/O */         int32_t
# 	fflags_t  st_flags;		/* user defined flags for file */           uint32_t
# 	__uint64_t st_gen;		/* file generation number */                uint64_t
# 	__uint64_t st_spare[10];                                            uint64_t * 10
# };
#
# struct timespec {
# 	time_t	tv_sec;		/* seconds */                                   uint64_t
# 	long	tv_nsec;	/* and nanoseconds */                           uint64_t (LP64 data model)
# };
#
#
# Assume no EXT.
class FreeBSDX86Stat(ctypes.Structure):
    _fields_ = [
        ("st_dev", ctypes.c_uint64),
        ("st_ino", ctypes.c_uint64),
        ("st_nlink", ctypes.c_uint64),
        ("st_mode", ctypes.c_uint16),
        ("st_padding0", ctypes.c_int16),
        ("st_uid", ctypes.c_uint32),
        ("st_gid", ctypes.c_uint32),
        ("st_padding1", ctypes.c_int32),
        ("st_rdev", ctypes.c_uint64),
        ("st_atime", ctypes.c_uint64),
        ("st_atime_ns", ctypes.c_uint64),
        ("st_mtime", ctypes.c_uint64),
        ("st_mtime_ns", ctypes.c_uint64),
        ("st_ctime", ctypes.c_uint64),
        ("st_ctime_ns", ctypes.c_uint64),
        ("st_birthtime", ctypes.c_uint64),
        ("st_birthtime_ns", ctypes.c_uint64),
        ("st_size", ctypes.c_int64),
        ("st_blocks", ctypes.c_int64),
        ("st_blksize", ctypes.c_int32),
        ("st_flags", ctypes.c_uint32),
        ("st_gen", ctypes.c_uint64),
        ("st_spare", ctypes.c_uint64 * 10)
    ]

    _pack_ = 4

class FreeBSDX8664Stat(ctypes.Structure):
    _fields_ = [
        ("st_dev", ctypes.c_uint64),
        ("st_ino", ctypes.c_uint64),
        ("st_nlink", ctypes.c_uint64),
        ("st_mode", ctypes.c_uint16),
        ("st_padding0", ctypes.c_int16),
        ("st_uid", ctypes.c_uint32),
        ("st_gid", ctypes.c_uint32),
        ("st_padding1", ctypes.c_int32),
        ("st_rdev", ctypes.c_uint64),
        ("st_atime", ctypes.c_uint64),
        ("st_atime_ns", ctypes.c_uint64),
        ("st_mtime", ctypes.c_uint64),
        ("st_mtime_ns", ctypes.c_uint64),
        ("st_ctime", ctypes.c_uint64),
        ("st_ctime_ns", ctypes.c_uint64),
        ("st_birthtime", ctypes.c_uint64),
        ("st_birthtime_ns", ctypes.c_uint64),
        ("st_size", ctypes.c_int64),
        ("st_blocks", ctypes.c_int64),
        ("st_blksize", ctypes.c_int32),
        ("st_flags", ctypes.c_uint32),
        ("st_gen", ctypes.c_uint64),
        ("st_spare", ctypes.c_uint64 * 10)
    ]

    _pack_ = 8

# Does FreeBSD really have stat64?
FreeBSDX86Stat64 = FreeBSDX86Stat
FreeBSDX8664Stat64 = FreeBSDX8664Stat

# https://opensource.apple.com/source/xnu/xnu-7195.81.3/bsd/sys/stat.h.auto.html
#
# m1 sizeof(long) = sizeof(intptr) = 8
#
# #define __DARWIN_STRUCT_STAT64_TIMES \
# struct timespec st_atimespec;           /* time of last access */ \
# struct timespec st_mtimespec;           /* time of last data modification */ \
# struct timespec st_ctimespec;           /* time of last status change */ \
# struct timespec st_birthtimespec;       /* time of file creation(birth) */
#
# #define __DARWIN_STRUCT_STAT64 { \
# 	dev_t		st_dev;                 /* [XSI] ID of device containing file */ \      int32_t
# 	mode_t		st_mode;                /* [XSI] Mode of file (see below) */ \          uint16_t
# 	nlink_t		st_nlink;               /* [XSI] Number of hard links */ \              uint16_t      
# 	__darwin_ino64_t st_ino;                /* [XSI] File serial number */ \            uint64_t
# 	uid_t		st_uid;                 /* [XSI] User ID of the file */ \               uint32_t
# 	gid_t		st_gid;                 /* [XSI] Group ID of the file */ \              uint32_t
# 	dev_t		st_rdev;                /* [XSI] Device ID */ \                         int32_t
# 	__DARWIN_STRUCT_STAT64_TIMES \                                                      uint64_t (long) * 8
# 	off_t		st_size;                /* [XSI] file size, in bytes */ \               int64_t
# 	blkcnt_t	st_blocks;              /* [XSI] blocks allocated for file */ \         int64_t
# 	blksize_t	st_blksize;             /* [XSI] optimal blocksize for I/O */ \         int32_t
# 	__uint32_t	st_flags;               /* user defined flags for file */ \             uint32_t
# 	__uint32_t	st_gen;                 /* file generation number */ \                  uint32_t
# 	__int32_t	st_lspare;              /* RESERVED: DO NOT USE! */ \                   int32_t
# 	__int64_t	st_qspare[2];           /* RESERVED: DO NOT USE! */ \                   int64_t * 2
# }
# /*
#  * [XSI] This structure is used as the second parameter to the fstat(),
#  * lstat(), and stat() functions.
#  */
# #if __DARWIN_64_BIT_INO_T

class MacOSStat(ctypes.Structure):
    _fields_ = [
        ("st_dev", ctypes.c_int32),
        ("st_mode", ctypes.c_uint16),
        ("st_nlink", ctypes.c_uint16),
        ("st_ino", ctypes.c_uint64),
        ("st_uid", ctypes.c_uint32),
        ("st_gid", ctypes.c_uint32),
        ("st_rdev", ctypes.c_int32),
        ("st_atime", ctypes.c_uint64),
        ("st_atime_ns", ctypes.c_uint64),
        ("st_mtime", ctypes.c_uint64),
        ("st_mtime_ns", ctypes.c_uint64),
        ("st_ctime", ctypes.c_uint64),
        ("st_ctime_ns", ctypes.c_uint64),
        ("st_birthtime", ctypes.c_uint64),
        ("st_birthtime_ns", ctypes.c_uint64),
        ("st_size", ctypes.c_int64),
        ("st_blocks", ctypes.c_int64),
        ("st_blksize", ctypes.c_int32),
        ("st_flags", ctypes.c_uint32),
        ("st_gen", ctypes.c_uint32),
        ("st_lspare", ctypes.c_int32),
        ("st_qspare", ctypes.c_int64 * 2)
    ]

    # No 32bit macos.
    _pack_ = 8

# They are the same in source code.
MacOSStat64 = MacOSStat

# https://elixir.bootlin.com/linux/latest/source/arch/mips/include/uapi/asm/stat.h#L19
#
# #if (_MIPS_SIM == _MIPS_SIM_ABI32) || (_MIPS_SIM == _MIPS_SIM_NABI32)
# struct stat {
# 	unsigned	st_dev;                                                             uint32_t
# 	long		st_pad1[3];		/* Reserved for network id */                       int32_t
# 	ino_t		st_ino;                                                             uint32_t (unsinged long)
# 	mode_t		st_mode;                                                            uint32_t (unsinged int)
# 	__u32		st_nlink;                                                           uint32_t
# 	uid_t		st_uid;                                                             uint32_t (unsigned int)
# 	gid_t		st_gid;                                                             uint32_t (unsigned int)
# 	unsigned	st_rdev;                                                            uint32_t
# 	long		st_pad2[2];                                                         uint32_t * 2
# 	long		st_size;                                                            uint32_t
# 	long		st_pad3;                                                            uint32_t
# 	/*
# 	 * Actually this should be timestruc_t st_atime, st_mtime and st_ctime
# 	 * but we don't have it under Linux.
# 	 */
# 	long		st_atime;                                                           uint32_t
# 	long		st_atime_nsec;                                                      uint32_t
# 	long		st_mtime;                                                           uint32_t
# 	long		st_mtime_nsec;                                                      uint32_t
# 	long		st_ctime;                                                           uint32_t
# 	long		st_ctime_nsec;                                                      uint32_t
# 	long		st_blksize;                                                         uint32_t
# 	long		st_blocks;                                                          uint32_t
# 	long		st_pad4[14];                                                        uint32_t * 4
# };
#
# struct stat64 {
# 	unsigned long	st_dev;                                                         uint32_t
# 	unsigned long	st_pad0[3];	/* Reserved for st_dev expansion  */                uint32_t * 3
# 	unsigned long long	st_ino;                                                     uint64_t
# 	mode_t		st_mode;                                                            uint32_t
# 	__u32		st_nlink;                                                           uint32_t
# 	uid_t		st_uid;                                                             uint32_t
# 	gid_t		st_gid;                                                             uint32_t
# 	unsigned long	st_rdev;                                                        uint32_t
# 	unsigned long	st_pad1[3];	/* Reserved for st_rdev expansion  */               uint32_t * 3
# 	long long	st_size;                                                            uint64_t
# 	/*
# 	 * Actually this should be timestruc_t st_atime, st_mtime and st_ctime
# 	 * but we don't have it under Linux.
# 	 */
# 	long		st_atime;                                                           int32_t
# 	unsigned long	st_atime_nsec;	/* Reserved for st_atime expansion  */          uint32_t
# 	long		st_mtime;                                                           int32_t
# 	unsigned long	st_mtime_nsec;	/* Reserved for st_mtime expansion  */          uint32_t
# 	long		st_ctime;                                                           int32_t
# 	unsigned long	st_ctime_nsec;	/* Reserved for st_ctime expansion  */          uint32_t
# 	unsigned long	st_blksize;                                                     uint32_t
# 	unsigned long	st_pad2;                                                        uint32_t
# 	long long	st_blocks;                                                          int64_t
# };
# #endif /* _MIPS_SIM == _MIPS_SIM_ABI32 */
# #if _MIPS_SIM == _MIPS_SIM_ABI64
# /* The memory layout is the same as of struct stat64 of the 32-bit kernel.  */
# struct stat {
# 	unsigned int		st_dev;                                                     uint32_t
# 	unsigned int		st_pad0[3]; /* Reserved for st_dev expansion */             uint32_t * 3
# 	unsigned long		st_ino;                                                     uint64_t
# 	mode_t			st_mode;                                                        uint32_t
# 	__u32			st_nlink;                                                       uint32_t
# 	uid_t			st_uid;                                                         uint32_t
# 	gid_t			st_gid;                                                         uint32_t
# 	unsigned int		st_rdev;                                                    uint32_t
# 	unsigned int		st_pad1[3]; /* Reserved for st_rdev expansion */            uint32_t * 3
# 	long			st_size;                                                        uint64_t
# 	/*
# 	 * Actually this should be timestruc_t st_atime, st_mtime and st_ctime
# 	 * but we don't have it under Linux.
# 	 */
# 	unsigned int		st_atime;                                                   uint32_t
# 	unsigned int		st_atime_nsec;                                              uint32_t
# 	unsigned int		st_mtime;                                                   uint32_t
# 	unsigned int		st_mtime_nsec;                                              uint32_t
# 	unsigned int		st_ctime;                                                   uint32_t
# 	unsigned int		st_ctime_nsec;                                              uint32_t
# 	unsigned int		st_blksize;                                                 uint32_t
# 	unsigned int		st_pad2;                                                    uint32_t
# 	unsigned long		st_blocks;                                                  uint64_t
# };

class LinuxMips32Stat(ctypes.Structure):
    _fields_ = [
        ("st_dev", ctypes.c_uint32),
        ("st_pad1", ctypes.c_int32 * 3),
        ("st_ino", ctypes.c_uint32),
        ("st_mode", ctypes.c_uint32),
        ("st_nlink", ctypes.c_uint32),
        ("st_uid", ctypes.c_uint32),
        ("st_gid", ctypes.c_uint32),
        ("st_rdev", ctypes.c_uint32),
        ("st_pad2", ctypes.c_uint32 * 2),
        ("st_size", ctypes.c_uint32),
        ("st_pad3", ctypes.c_uint32),
        ("st_atime", ctypes.c_uint32),
        ("st_atime_ns", ctypes.c_uint32),
        ("st_mtime", ctypes.c_uint32),
        ("st_mtime_ns", ctypes.c_uint32),
        ("st_ctime", ctypes.c_uint32),
        ("st_ctime_ns", ctypes.c_uint32),
        ("st_blksize", ctypes.c_uint32),
        ("st_blocks", ctypes.c_uint32),
        ("st_pad4", ctypes.c_uint32 * 14)
    ]

    _pack_ = 4

class LinuxMips64Stat(ctypes.Structure):
    _fields_ = [
        ("st_dev", ctypes.c_uint32),
        ("st_pad0", ctypes.c_uint32 * 3),
        ("st_ino", ctypes.c_uint64),
        ("st_mode", ctypes.c_uint32),
        ("st_nlink", ctypes.c_uint32),
        ("st_uid", ctypes.c_uint32),
        ("st_gid", ctypes.c_uint32),
        ("st_rdev", ctypes.c_uint32),
        ("st_pad1", ctypes.c_uint32 * 3),
        ("st_size", ctypes.c_uint64),
        ("st_atime", ctypes.c_uint32),
        ("st_atime_ns", ctypes.c_uint32),
        ("st_mtime", ctypes.c_uint32),
        ("st_mtime_ns", ctypes.c_uint32),
        ("st_ctime", ctypes.c_uint32),
        ("st_ctime_ns", ctypes.c_uint32),
        ("st_blksize", ctypes.c_uint32),
        ("st_pad2", ctypes.c_uint32),
        ("st_blocks", ctypes.c_uint64)
    ]

    _pack_ = 8

class LinuxMips32Stat64(ctypes.Structure):
    _fields_ = [
        ("st_dev", ctypes.c_uint32),
        ("st_pad0", ctypes.c_uint32 * 3),
        ("st_ino", ctypes.c_uint64),
        ("st_mode", ctypes.c_uint32),
        ("st_nlink", ctypes.c_uint32),
        ("st_uid", ctypes.c_uint32),
        ("st_gid", ctypes.c_uint32),
        ("st_rdev", ctypes.c_uint32),
        ("st_pad1", ctypes.c_uint32 * 3),
        ("st_size", ctypes.c_uint64),
        ("st_atime", ctypes.c_int32),
        ("st_atime_ns", ctypes.c_uint32),
        ("st_mtime", ctypes.c_int32),
        ("st_mtime_ns", ctypes.c_uint32),
        ("st_ctime", ctypes.c_int32),
        ("st_ctime_ns", ctypes.c_uint32),
        ("st_blksize", ctypes.c_uint32),
        ("st_pad2", ctypes.c_uint32),
        ("st_blocks", ctypes.c_int64)
    ]

    _pack_ = 4

# https://elixir.bootlin.com/linux/latest/source/arch/x86/include/uapi/asm/stat.h#L10
#
# #ifdef __i386__
# struct stat {
# 	unsigned long  st_dev;                                                      uint32_t
# 	unsigned long  st_ino;                                                      uint32_t
# 	unsigned short st_mode;                                                     uint16_t
# 	unsigned short st_nlink;                                                    uint16_t
# 	unsigned short st_uid;                                                      uint16_t
# 	unsigned short st_gid;                                                      uint16_t
# 	unsigned long  st_rdev;                                                     uint32_t
# 	unsigned long  st_size;                                                     uint32_t
# 	unsigned long  st_blksize;                                                  uint32_t
# 	unsigned long  st_blocks;                                                   uint32_t
# 	unsigned long  st_atime;                                                    uint32_t
# 	unsigned long  st_atime_nsec;                                               uint32_t
# 	unsigned long  st_mtime;                                                    uint32_t
# 	unsigned long  st_mtime_nsec;                                               uint32_t
# 	unsigned long  st_ctime;                                                    uint32_t
# 	unsigned long  st_ctime_nsec;                                               uint32_t
# 	unsigned long  __unused4;                                                   uint32_t
# 	unsigned long  __unused5;                                                   uint32_t
# };
# struct stat64 {
# 	unsigned long long	st_dev;                                                 uint64_t
# 	unsigned char	__pad0[4];                                                  uint8_t * 4
# 	unsigned long	__st_ino;                                                   uint32_t
# 	unsigned int	st_mode;                                                    uint32_t
# 	unsigned int	st_nlink;                                                   uint32_t
# 	unsigned long	st_uid;                                                     uint32_t
# 	unsigned long	st_gid;                                                     uint32_t
# 	unsigned long long	st_rdev;                                                uint64_t
# 	unsigned char	__pad3[4];                                                  uint8_t * 4
# 	long long	st_size;                                                        int64_t
# 	unsigned long	st_blksize;                                                 uint32_t
# 	/* Number 512-byte blocks allocated. */
# 	unsigned long long	st_blocks;                                              uint64_t
# 	unsigned long	st_atime;                                                   uint32_t
# 	unsigned long	st_atime_nsec;                                              uint32_t
# 	unsigned long	st_mtime;                                                   uint32_t
# 	unsigned int	st_mtime_nsec;                                              uint32_t
# 	unsigned long	st_ctime;                                                   uint32_t
# 	unsigned long	st_ctime_nsec;                                              uint32_t
# 	unsigned long long	st_ino;                                                 uint64_t
# };
# #else /* __i386__ */
# struct stat {
# 	__kernel_ulong_t	st_dev;                                                 uint64_t
# 	__kernel_ulong_t	st_ino;                                                 uint64_t
# 	__kernel_ulong_t	st_nlink;                                               uint64_t
# 	unsigned int		st_mode;                                                uint32_t
# 	unsigned int		st_uid;                                                 uint32_t
# 	unsigned int		st_gid;                                                 uint32_t
# 	unsigned int		__pad0;                                                 uint32_t
# 	__kernel_ulong_t	st_rdev;                                                uint64_t
# 	__kernel_long_t		st_size;                                                int64_t
# 	__kernel_long_t		st_blksize;                                             int64_t
# 	__kernel_long_t		st_blocks;	/* Number 512-byte blocks allocated. */     int64_t
# 	__kernel_ulong_t	st_atime;                                               uint64_t
# 	__kernel_ulong_t	st_atime_nsec;                                          uint64_t
# 	__kernel_ulong_t	st_mtime;                                               uint64_t
# 	__kernel_ulong_t	st_mtime_nsec;                                          uint64_t
# 	__kernel_ulong_t	st_ctime;                                               uint64_t
# 	__kernel_ulong_t	st_ctime_nsec;                                          uint64_t
# 	__kernel_long_t		__unused[3];                                            int64_t
# };
# #endif

class LinuxX86Stat(ctypes.Structure):
    _fields_ = [
        ("st_dev", ctypes.c_uint32),
        ("st_ino", ctypes.c_uint32),
        ("st_mode", ctypes.c_uint16),
        ("st_nlink", ctypes.c_uint16),
        ("st_uid", ctypes.c_uint16),
        ("st_gid", ctypes.c_uint16),
        ("st_rdev", ctypes.c_uint32),
        ("st_size", ctypes.c_uint32),
        ("st_blksize", ctypes.c_uint32),
        ("st_blocks", ctypes.c_uint32),
        ("st_atime", ctypes.c_uint32),
        ("st_atime_ns", ctypes.c_uint32),
        ("st_mtime", ctypes.c_uint32),
        ("st_mtime_ns", ctypes.c_uint32),
        ("st_ctime", ctypes.c_uint32),
        ("st_ctime_ns", ctypes.c_uint32),
        ("__unused4", ctypes.c_uint32),
        ("__unused5", ctypes.c_uint32)
    ]

    _pack_ = 4

class LinuxX8664Stat(ctypes.Structure):
    _fields_ = [
        ("st_dev", ctypes.c_uint64),
        ("st_ino", ctypes.c_uint64),
        ("st_nlink", ctypes.c_uint64),
        ("st_mode", ctypes.c_uint32),
        ("st_uid", ctypes.c_uint32),
        ("st_gid", ctypes.c_uint32),
        ("__pad0", ctypes.c_uint32),
        ("st_rdev", ctypes.c_uint64),
        ("st_size", ctypes.c_int64),
        ("st_blksize", ctypes.c_int64),
        ("st_blocks", ctypes.c_int64),
        ("st_atime", ctypes.c_uint64),
        ("st_atime_ns", ctypes.c_uint64),
        ("st_mtime", ctypes.c_uint64),
        ("st_mtime_ns", ctypes.c_uint64),
        ("st_ctime", ctypes.c_uint64),
        ("st_ctime_ns", ctypes.c_uint64),
        ("__unused", ctypes.c_int64 * 3),
    ]

    _pack_ = 8

class LinuxX86Stat64(ctypes.Structure):
    _fields_ = [
        ("st_dev", ctypes.c_uint64),
        ("__pad0", ctypes.c_uint8 * 4),
        ("__st_ino", ctypes.c_uint32),
        ("st_mode", ctypes.c_uint32),
        ("st_nlink", ctypes.c_uint32),
        ("st_uid", ctypes.c_uint32),
        ("st_gid", ctypes.c_uint32),
        ("st_rdev", ctypes.c_uint64),
        ("__pad3", ctypes.c_uint8 * 4),
        ("st_size", ctypes.c_int64),
        ("st_blksize", ctypes.c_uint32),
        ("st_blocks", ctypes.c_uint64),
        ("st_atime", ctypes.c_uint32),
        ("st_atime_ns", ctypes.c_uint32),
        ("st_mtime", ctypes.c_uint32),
        ("st_mtime_ns", ctypes.c_uint32),
        ("st_ctime", ctypes.c_uint32),
        ("st_ctime_ns", ctypes.c_uint32),
        ("st_ino", ctypes.c_uint64)
    ]

    _pack_ = 4

# https://elixir.bootlin.com/linux/latest/source/arch/arm/include/uapi/asm/stat.h#L21
#
# struct stat {
# #if defined(__ARMEB__)
# 	unsigned short st_dev;                                                          uint16_t
# 	unsigned short __pad1;                                                          uint16_t
# #else
# 	unsigned long  st_dev;                                                          uint32_t
# #endif
# 	unsigned long  st_ino;                                                          uint32_t
# 	unsigned short st_mode;                                                         uint16_t
# 	unsigned short st_nlink;                                                        uint16_t
# 	unsigned short st_uid;                                                          uint16_t
# 	unsigned short st_gid;                                                          uint16_t
# #if defined(__ARMEB__)
# 	unsigned short st_rdev;                                                         uint16_t
# 	unsigned short __pad2;                                                          uint16_t
# #else
# 	unsigned long  st_rdev;                                                         uint32_t
# #endif
# 	unsigned long  st_size;                                                         uint32_t
# 	unsigned long  st_blksize;                                                      uint32_t
# 	unsigned long  st_blocks;                                                       uint32_t
# 	unsigned long  st_atime;                                                        uint32_t
# 	unsigned long  st_atime_nsec;                                                   uint32_t
# 	unsigned long  st_mtime;                                                        uint32_t
# 	unsigned long  st_mtime_nsec;                                                   uint32_t
# 	unsigned long  st_ctime;                                                        uint32_t
# 	unsigned long  st_ctime_nsec;                                                   uint32_t
# 	unsigned long  __unused4;                                                       uint32_t
# 	unsigned long  __unused5;                                                       uint32_t
# };

# struct stat64 {
# 	unsigned long long	st_dev;                                                     uint64_t
# 	unsigned char   __pad0[4];                                                      uint8_t * 4
# #define STAT64_HAS_BROKEN_ST_INO	1
# 	unsigned long	__st_ino;                                                       uint32_t
# 	unsigned int	st_mode;                                                        uint32_t
# 	unsigned int	st_nlink;                                                       uint32_t
# 	unsigned long	st_uid;                                                         uint32_t
# 	unsigned long	st_gid;                                                         uint32_t
# 	unsigned long long	st_rdev;                                                    uint64_t
# 	unsigned char   __pad3[4];                                                      uint8_t * 4
# 	long long	st_size;                                                            int64_t
# 	unsigned long	st_blksize;                                                     uint32_t
# 	unsigned long long st_blocks;	/* Number 512-byte blocks allocated. */         uint64_t
# 	unsigned long	st_atime;                                                       uint32_t
# 	unsigned long	st_atime_nsec;                                                  uint32_t
# 	unsigned long	st_mtime;                                                       uint32_t
# 	unsigned long	st_mtime_nsec;                                                  uint32_t
# 	unsigned long	st_ctime;                                                       uint32_t
# 	unsigned long	st_ctime_nsec;                                                  uint32_t
# 	unsigned long long	st_ino;                                                     uint64_t
# };

# ARM64 stat is different!
# https://elixir.bootlin.com/linux/v4.20.17/source/arch/arm64/include/asm/stat.h
# The stat.h above includes https://elixir.bootlin.com/linux/v4.20.17/source/arch/arm64/include/uapi/asm/stat.h
# struct stat {
# 	unsigned long	st_dev;		/* Device.  */                                      uint64_t
# 	unsigned long	st_ino;		/* File serial number.  */                          uint64_t
# 	unsigned int	st_mode;	/* File mode.  */                                   uint32_t
# 	unsigned int	st_nlink;	/* Link count.  */                                  uint32_t
# 	unsigned int	st_uid;		/* User ID of the file's owner.  */                 uint32_t
# 	unsigned int	st_gid;		/* Group ID of the file's group. */                 uint32_t
# 	unsigned long	st_rdev;	/* Device number, if device.  */                    uint64_t
# 	unsigned long	__pad1;                                                         uint64_t
# 	long		st_size;	/* Size of file, in bytes.  */                          int64_t
# 	int		st_blksize;	/* Optimal block size for I/O.  */                          int32_t
# 	int		__pad2;                                                                 int32_t
# 	long		st_blocks;	/* Number 512-byte blocks allocated. */                 int64_t
# 	long		st_atime;	/* Time of last access.  */                             int64_t
# 	unsigned long	st_atime_nsec;                                                  uint64_t
# 	long		st_mtime;	/* Time of last modification.  */                       int64_t
# 	unsigned long	st_mtime_nsec;                                                  uint64_t
# 	long		st_ctime;	/* Time of last status change.  */                      int64_t
# 	unsigned long	st_ctime_nsec;                                                  uint64_t
# 	unsigned int	__unused4;                                                      uint32_t
# 	unsigned int	__unused5;                                                      uint32_t
# };

class LinuxARMStat(ctypes.Structure):
    _fields_ = [
        ("st_dev", ctypes.c_uint32),
        ("st_ino", ctypes.c_uint32),
        ("st_mode", ctypes.c_uint16),
        ("st_nlink", ctypes.c_uint16),
        ("st_uid", ctypes.c_uint16),
        ("st_gid", ctypes.c_uint16),
        ("st_rdev", ctypes.c_uint32),
        ("st_size", ctypes.c_uint32),
        ("st_blksize", ctypes.c_uint32),
        ("st_blocks", ctypes.c_uint32),
        ("st_atime", ctypes.c_uint32),
        ("st_atime_ns", ctypes.c_uint32),
        ("st_mtime", ctypes.c_uint32),
        ("st_mtime_ns", ctypes.c_uint32),
        ("st_ctime", ctypes.c_uint32),
        ("st_ctime_ns", ctypes.c_uint32),
        ("__unused4", ctypes.c_uint32),
        ("__unused6", ctypes.c_uint32)
    ]

    _pack_ = 8

class LinuxARM64Stat(ctypes.Structure):
    _fields_ = [
        ("st_dev", ctypes.c_uint64),
        ("st_ino", ctypes.c_uint64),
        ("st_mode", ctypes.c_uint32),
        ("st_nlink", ctypes.c_uint32),
        ("st_uid", ctypes.c_uint32),
        ("st_gid", ctypes.c_uint32),
        ("st_rdev", ctypes.c_uint64),
        ("__pad1", ctypes.c_uint64),
        ("st_size", ctypes.c_int64),
        ("st_blksize", ctypes.c_int32),
        ("__pad2", ctypes.c_int32),
        ("st_blocks", ctypes.c_int64),
        ("st_atime", ctypes.c_int64),
        ("st_atime_ns", ctypes.c_uint64),
        ("st_mtime", ctypes.c_int64),
        ("st_mtime_ns", ctypes.c_uint64),
        ("st_ctime", ctypes.c_int64),
        ("st_ctime_ns", ctypes.c_uint64),
        ("__unused4", ctypes.c_uint32),
        ("__unused5", ctypes.c_uint32)
    ]

    _pack_ = 8

class LinuxARMEBStat(ctypes.BigEndianStructure):
    _fields_ = [
        ("st_dev", ctypes.c_uint16),
        ("__pad1", ctypes.c_uint16),
        ("st_mode", ctypes.c_uint16),
        ("st_nlink", ctypes.c_uint16),
        ("st_uid", ctypes.c_uint16),
        ("st_gid", ctypes.c_uint16),
        ("st_rdev", ctypes.c_uint16),
        ("__pad1", ctypes.c_uint16),
        ("st_size", ctypes.c_uint32),
        ("st_blksize", ctypes.c_uint32),
        ("st_blocks", ctypes.c_uint32),
        ("st_atime", ctypes.c_uint32),
        ("st_atime_ns", ctypes.c_uint32),
        ("st_mtime", ctypes.c_uint32),
        ("st_mtime_ns", ctypes.c_uint32),
        ("st_ctime", ctypes.c_uint32),
        ("st_ctime_ns", ctypes.c_uint32),
        ("__unused4", ctypes.c_uint32),
        ("__unused5", ctypes.c_uint32)
    ]

    _pack_ = 8

class LinuxARMStat64(ctypes.Structure):
    _fields_ = [
        ("st_dev", ctypes.c_uint64),
        ("__pad0", ctypes.c_uint8 * 4),
        ("__st_ino", ctypes.c_uint32),
        ("st_mode", ctypes.c_uint32),
        ("st_nlink", ctypes.c_uint32),
        ("st_uid", ctypes.c_uint32),
        ("st_gid", ctypes.c_uint32),
        ("st_rdev", ctypes.c_uint64),
        ("__pad3", ctypes.c_uint8 * 4),
        ("st_size", ctypes.c_int64),
        ('st_blksize', ctypes.c_int32),
        ("st_blocks", ctypes.c_uint64),
        ("st_atime", ctypes.c_uint32),
        ("st_atime_ns", ctypes.c_uint32),
        ("st_mtime", ctypes.c_uint32),
        ("st_mtime_ns", ctypes.c_uint32),
        ("st_ctime", ctypes.c_uint32),
        ("st_ctime_ns", ctypes.c_uint32),
        ("st_ino", ctypes.c_uint64),
    ]

    _pack_ = 8

class LinuxARMEBStat64(ctypes.BigEndianStructure):
    _fields_ = [
        ("st_dev", ctypes.c_uint64),
        ("__pad0", ctypes.c_uint8 * 4),
        ("__st_ino", ctypes.c_uint32),
        ("st_mode", ctypes.c_uint32),
        ("st_nlink", ctypes.c_uint32),
        ("st_uid", ctypes.c_uint32),
        ("st_gid", ctypes.c_uint32),
        ("st_rdev", ctypes.c_uint64),
        ("__pad3", ctypes.c_uint8 * 4),
        ("st_size", ctypes.c_int64),
        ('st_blksize', ctypes.c_int32),
        ("st_blocks", ctypes.c_uint64),
        ("st_atime", ctypes.c_uint32),
        ("st_atime_ns", ctypes.c_uint32),
        ("st_mtime", ctypes.c_uint32),
        ("st_mtime_ns", ctypes.c_uint32),
        ("st_ctime", ctypes.c_uint32),
        ("st_ctime_ns", ctypes.c_uint32),
        ("st_ino", ctypes.c_uint64),
    ]

    _pack_ = 8

class LinuxARM64EBStat(ctypes.BigEndianStructure):
    _fields_ = [
        ("st_dev", ctypes.c_uint64),
        ("st_ino", ctypes.c_uint64),
        ("st_mode", ctypes.c_uint32),
        ("st_nlink", ctypes.c_uint32),
        ("st_uid", ctypes.c_uint32),
        ("st_gid", ctypes.c_uint32),
        ("st_rdev", ctypes.c_uint64),
        ("__pad1", ctypes.c_uint64),
        ("st_size", ctypes.c_int64),
        ("st_blksize", ctypes.c_int32),
        ("__pad2", ctypes.c_int32),
        ("st_blocks", ctypes.c_int64),
        ("st_atime", ctypes.c_int64),
        ("st_atime_ns", ctypes.c_uint64),
        ("st_mtime", ctypes.c_int64),
        ("st_mtime_ns", ctypes.c_uint64),
        ("st_ctime", ctypes.c_int64),
        ("st_ctime_ns", ctypes.c_uint64),
        ("__unused4", ctypes.c_uint32),
        ("__unused5", ctypes.c_uint32)
    ]

    _pack_ = 8

# Source: openqnx lib/c/public/sys/stat.h
#
# struct stat {
# #if _FILE_OFFSET_BITS - 0 == 64
# 	ino_t			st_ino;			/* File serial number.					*/
# 	off_t			st_size;
# #elif !defined(_FILE_OFFSET_BITS) || _FILE_OFFSET_BITS == 32
# #if defined(__LITTLEENDIAN__)
# 	ino_t			st_ino;			/* File serial number.					*/
# 	ino_t			st_ino_hi;
# 	off_t			st_size;
# 	off_t			st_size_hi;
# #elif defined(__BIGENDIAN__)
# 	ino_t			st_ino_hi;
# 	ino_t			st_ino;			/* File serial number.					*/
# 	off_t			st_size_hi;
# 	off_t			st_size;
# #else
#  #error endian not configured for system
# #endif
# #else
#  #error _FILE_OFFSET_BITS value is unsupported
# #endif
# 	_CSTD dev_t		st_dev;			/* ID of device containing file.		*/
# 	_CSTD dev_t		st_rdev;		/* Device ID, for inode that is device	*/
# 	uid_t			st_uid;
# 	gid_t			st_gid;
# 	_CSTD time_t	st_mtime;		/* Time of last data modification		*/
# 	_CSTD time_t	st_atime;		/* Time last accessed					*/
# 	_CSTD time_t	st_ctime;		/* Time of last status change			*/
# 	_CSTD mode_t	st_mode;		/* see below							*/
# 	nlink_t			st_nlink;
# 	blksize_t		st_blocksize;	/* Size of a block used by st_nblocks   */
# 	_Int32t			st_nblocks;		/* Number of blocks st_blocksize blocks */
# 	blksize_t		st_blksize;		/* Prefered I/O block size for object   */
# #if _FILE_OFFSET_BITS - 0 == 64
# 	blkcnt_t		st_blocks;		/* Number of 512 byte blocks			*/
# #elif !defined(_FILE_OFFSET_BITS) || _FILE_OFFSET_BITS == 32
# #if defined(__LITTLEENDIAN__)
# 	blkcnt_t		st_blocks;
# 	blkcnt_t		st_blocks_hi;
# #elif defined(__BIGENDIAN__)
# 	blkcnt_t		st_blocks_hi;
# 	blkcnt_t		st_blocks;
# #else
#  #error endian not configured for system
# #endif
# #else
#  #error _FILE_OFFSET_BITS value is unsupported
# #endif
# };

# struct stat64 {
# 	ino64_t			st_ino;			/* File serial number.					*/
# 	off64_t			st_size;
# 	_CSTD dev_t		st_dev;			/* ID of device containing file.		*/
# 	_CSTD dev_t		st_rdev;		/* Device ID, for inode that is device	*/
# 	uid_t			st_uid;
# 	gid_t			st_gid;
# 	_CSTD time_t	st_mtime;		/* Time of last data modification		*/
# 	_CSTD time_t	st_atime;		/* Time last accessed					*/
# 	_CSTD time_t	st_ctime;		/* Time of last status change			*/
# 	_CSTD mode_t	st_mode;		/* see below							*/
# 	nlink_t			st_nlink;
# 	blksize_t		st_blocksize;	/* Size of a block used by st_nblocks   */
# 	_Int32t			st_nblocks;		/* Number of blocks st_blocksize blocks */
# 	blksize_t		st_blksize;		/* Prefered I/O block size for object   */
# 	blkcnt64_t		st_blocks;		/* Number of 512 byte blocks			*/
# };

class QNXARMStat(ctypes.Structure):
    _fields_ = [
        ("st_ino", ctypes.c_uint32),
        ("st_ino_hi", ctypes.c_uint32), # this field must be zero
        ("st_size", ctypes.c_uint32),
        ("st_size_hi", ctypes.c_uint32), # this field must be zero
        ("st_dev", ctypes.c_uint32),
        ("st_rdev", ctypes.c_uint32),
        ("st_uid", ctypes.c_int32),
        ("st_gid", ctypes.c_int32),
        ("st_mtime", ctypes.c_uint32),
        ("st_atime", ctypes.c_uint32),
        ("st_ctime", ctypes.c_uint32),
        ("st_mode", ctypes.c_uint32),
        ("st_nlink", ctypes.c_uint32),
        ("st_blksize", ctypes.c_uint32),
        ("st_blocks", ctypes.c_uint32),
        ("st_blksize", ctypes.c_uint32),
        ("st_blocks", ctypes.c_uint32),
        ("st_blocks_hi", ctypes.c_uint32) # this field must be zero
    ]

    _pack_ = 4

class QNXARM64Stat(ctypes.Structure):
    _fields_ = [
        ("st_ino", ctypes.c_uint64),
        ("st_size", ctypes.c_uint64),
        ("st_dev", ctypes.c_uint32),
        ("st_rdev", ctypes.c_uint32),
        ("st_uid", ctypes.c_int32),
        ("st_gid", ctypes.c_int32),
        ("st_mtime", ctypes.c_uint32),
        ("st_atime", ctypes.c_uint32),
        ("st_ctime", ctypes.c_uint32),
        ("st_mode", ctypes.c_uint32),
        ("st_nlink", ctypes.c_uint32),
        ("st_blksize", ctypes.c_uint32),
        ("st_blocks", ctypes.c_int32),
        ("st_blksize", ctypes.c_uint32),
        ("st_blocks", ctypes.c_uint64)
    ]

    _pack_ = 8

class QNXARMEBStat(ctypes.BigEndianStructure):
    _fields_ = [
        ("st_ino_hi", ctypes.c_uint32), # this field must be zero
        ("st_ino", ctypes.c_uint32),
        ("st_size_hi", ctypes.c_uint32), # this field must be zero
        ("st_size", ctypes.c_uint32),
        ("st_dev", ctypes.c_uint32),
        ("st_rdev", ctypes.c_uint32),
        ("st_uid", ctypes.c_int32),
        ("st_gid", ctypes.c_int32),
        ("st_mtime", ctypes.c_uint32),
        ("st_atime", ctypes.c_uint32),
        ("st_ctime", ctypes.c_uint32),
        ("st_mode", ctypes.c_uint32),
        ("st_nlink", ctypes.c_uint32),
        ("st_blksize", ctypes.c_uint32),
        ("st_blocks", ctypes.c_uint32),
        ("st_blksize", ctypes.c_uint32),
        ("st_blocks_hi", ctypes.c_uint32), # this field must be zero
        ("st_blocks", ctypes.c_uint32)
    ]

    _pack_ = 4

class QNXARMStat64(ctypes.Structure):
    _fields_ = [
        ("st_ino", ctypes.c_uint64),
        ("st_size", ctypes.c_uint64),
        ("st_dev", ctypes.c_uint32),
        ("st_rdev", ctypes.c_uint32),
        ("st_uid", ctypes.c_int32),
        ("st_gid", ctypes.c_int32),
        ("st_mtime", ctypes.c_uint32),
        ("st_atime", ctypes.c_uint32),
        ("st_ctime", ctypes.c_uint32),
        ("st_mode", ctypes.c_uint32),
        ("st_nlink", ctypes.c_uint32),
        ("st_blksize", ctypes.c_uint32),
        ("st_blocks", ctypes.c_uint32),
        ("st_blksize", ctypes.c_uint32),
        ("st_blocks", ctypes.c_uint64)
    ]

    _pack_ = 8

def get_stat64_struct(ql: Qiling):
    if ql.archbit == 64:
        ql.log.warning(f"Trying to stat64 on a 64bit system with {ql.ostype} and {ql.archtype}!")
    if ql.ostype == QL_OS.LINUX:
        if ql.archtype == QL_ARCH.X86:
            return LinuxX86Stat64()
        elif ql.archtype == QL_ARCH.MIPS:
            return LinuxMips32Stat64()
        elif ql.archtype in (QL_ARCH.ARM, QL_ARCH.ARM_THUMB):
            return LinuxARMStat64()
    elif ql.ostype == QL_OS.MACOS:
        return MacOSStat64()
    elif ql.ostype == QL_OS.QNX:
        return QNXARMStat64()
    ql.log.warning(f"Unrecognized arch && os with {ql.archtype} and {ql.ostype} for stat64! Fallback to Linux x86.")
    return LinuxX86Stat64()

def get_stat_struct(ql: Qiling):
    if ql.ostype == QL_OS.FREEBSD:
        if ql.archtype == QL_ARCH.X8664 or ql.archbit == 64:
            return FreeBSDX8664Stat()
        else:
            return FreeBSDX86Stat()
    elif ql.ostype == QL_OS.MACOS:
        return MacOSStat()
    elif ql.ostype == QL_OS.LINUX:
        if ql.archtype == QL_ARCH.X8664:
            return LinuxX8664Stat()
        elif ql.archtype == QL_ARCH.X86:
            return LinuxX86Stat()
        elif ql.archtype == QL_ARCH.MIPS:
            if ql.archbit == 64:
                return LinuxMips64Stat()
            else:
                return LinuxMips32Stat()
        elif ql.archtype in (QL_ARCH.ARM, QL_ARCH.ARM_THUMB):
            if ql.archendian == QL_ENDIAN.EL:
                return LinuxARMStat()
            else:
                return LinuxARMEBStat()
        elif ql.archtype == QL_ARCH.ARM64:
            if ql.archendian == QL_ENDIAN.EL:
                return LinuxARM64Stat()
            else:
                return LinuxARM64EBStat()
    elif ql.ostype == QL_OS.QNX:
        if ql.archtype == QL_ARCH.ARM64:
            return QNXARM64Stat()
        elif ql.archtype == QL_ARCH.ARM:
            if ql.archendian == QL_ENDIAN.EL:
                return QNXARMStat()
            else:
                return QNXARMEBStat()
    ql.log.warning(f"Unrecognized arch && os with {ql.archtype} and {ql.ostype} for stat! Fallback to Linux x86.")
    return LinuxX86Stat()

def __common_pack_stat_struct(stat, info) -> bytes:
    for field, _ in stat._fields_:
        val = stat.__getattribute__(field)

        if isinstance(val, ctypes.Array):
            stat.__setattr__(field, (0,) * len(val))
        else:
            stat.__setattr__(field, int(info[field]))

    return bytes(stat)


def pack_stat_struct(ql: Qiling, info):
    stat = get_stat_struct(ql)

    return __common_pack_stat_struct(stat, info)

def pack_stat64_struct(ql: Qiling, info):
    stat = get_stat64_struct(ql)

    return __common_pack_stat_struct(stat, info)

def statFamily(ql: Qiling, path: int, ptr: int, name: str, stat_func, struct_func: Callable):
    file_path = ql.os.utils.read_cstring(path)
    real_path = ql.os.path.transform_to_real_path(file_path)
    regreturn = 0

    try:
        info = stat_func(real_path)
    except OSError as e:
        ql.log.debug(f'{name}("{file_path}", {ptr:#x}) read/write fail')
        return -e.errno
    else:
        buf = struct_func(ql, info)
        ql.mem.write(ptr, buf)
        ql.log.debug(f'{name}("{file_path}", {ptr:#x}) write completed')
        return regreturn

def ql_syscall_chmod(ql: Qiling, filename: int, mode: int):
    ql.log.debug(f'chmod("{ql.os.utils.read_cstring(filename)}", {mode:d}) = 0')

    return 0

def ql_syscall_fchmod(ql: Qiling, fd: int, mode: int):
    if not (0 < fd < NR_OPEN) or ql.os.fd[fd] == 0:
        return -EBADF

    return 0

def ql_syscall_fstatat64(ql: Qiling, dirfd: int, path: int, buf_ptr: int, flag: int):
    # FIXME: dirfd(relative path) not implement.
    file_path = ql.os.utils.read_cstring(path)
    real_path = ql.os.path.transform_to_real_path(file_path)
    relative_path = ql.os.path.transform_to_relative_path(file_path)

    if os.path.exists(real_path):
        buf = pack_stat64_struct(ql, Stat(real_path))
        ql.mem.write(buf_ptr, buf)

        regreturn = 0
    else:
        regreturn = -1

    ql.log.debug(f'Directory {"found" if regreturn == 0 else "not found"}: {relative_path}')

    return regreturn

def ql_syscall_newfstatat(ql: Qiling, dirfd: int, path: int, buf_ptr: int, flag: int):
    # FIXME: dirfd(relative path) not implement.
    file_path = ql.os.utils.read_cstring(path)
    real_path = ql.os.path.transform_to_real_path(file_path)
    relative_path = ql.os.path.transform_to_relative_path(file_path)

    if os.path.exists(real_path):
        buf = pack_stat_struct(ql, Stat(real_path))
        ql.mem.write(buf_ptr, buf)

        regreturn = 0
    else:
        regreturn = -1

    ql.log.debug(f'Directory {"found" if regreturn == 0 else "not found"}: {relative_path}')

    return regreturn

def ql_syscall_fstat64(ql: Qiling, fd, buf_ptr):
    if not hasattr(ql.os.fd[fd], "fstat"):
        regreturn = -1
    elif ql.os.fd[fd].fstat() == -1:
        regreturn = 0
    elif 0 <= fd < NR_OPEN and ql.os.fd[fd] != 0:
        buf = pack_stat64_struct(ql, ql.os.fd[fd].fstat())
        ql.mem.write(buf_ptr, buf)

        regreturn = 0
    else:
        regreturn = -1

    if regreturn == 0:
        ql.log.debug("fstat64 write completed")
    else:
        ql.log.debug("fstat64 read/write fail")

    return regreturn


def ql_syscall_fstat(ql: Qiling, fd, buf_ptr):
    if not hasattr(ql.os.fd[fd], "fstat"):
        regreturn = -1
    # elif ql.os.fd[fd].fstat() == -1:
    #     regreturn = 0
    elif 0 <= fd < NR_OPEN and ql.os.fd[fd] != 0:
        buf = pack_stat_struct(ql,  ql.os.fd[fd].fstat())
        ql.mem.write(buf_ptr, buf)

        regreturn = 0
    else:
        regreturn = -1

    if regreturn == 0:
        ql.log.debug("fstat write completed")
    else:
        ql.log.debug("fstat read/write fail")

    return regreturn


# int stat(const char *path, struct stat *buf);
def ql_syscall_stat(ql: Qiling, path: int, buf_ptr: int):
    return statFamily(ql, path, buf_ptr, "stat", Stat, pack_stat_struct)


# int stat64(const char *path, struct stat64 *buf);
def ql_syscall_stat64(ql: Qiling, path: int, buf_ptr: int):
    return statFamily(ql, path, buf_ptr, "stat64", Stat, pack_stat64_struct)


def ql_syscall_lstat(ql: Qiling, path: int, buf_ptr: int):
    return statFamily(ql, path, buf_ptr, "lstat", Lstat, pack_stat64_struct)


def ql_syscall_lstat64(ql: Qiling, path: int, buf_ptr: int):
    return statFamily(ql, path, buf_ptr, "lstat64", Lstat, pack_stat64_struct)


def ql_syscall_mknodat(ql: Qiling, dirfd: int, pathname: int, mode: int, dev: int):
    # FIXME: dirfd(relative path) not implement.
    file_path = ql.os.utils.read_cstring(pathname)
    real_path = ql.os.path.transform_to_real_path(file_path)
    regreturn = 0

    try:
        os.mknod(real_path, mode, dev)
    except:
        regreturn = -1

    return regreturn


def ql_syscall_mkdir(ql: Qiling, pathname: int, mode: int):
    file_path = ql.os.utils.read_cstring(pathname)
    real_path = ql.os.path.transform_to_real_path(file_path)
    regreturn = 0

    try:
        if not os.path.exists(real_path):
            os.mkdir(real_path, mode)
    except:
        regreturn = -1

    return regreturn

def ql_syscall_rmdir(ql: Qiling, pathname: int):
    file_path = ql.os.utils.read_cstring(pathname)
    real_path = ql.os.path.transform_to_real_path(file_path)
    regreturn = 0

    try:
        if os.path.exists(real_path):
            os.rmdir(real_path)
    except:
        regreturn = -1

    return regreturn

def ql_syscall_fstatfs(ql: Qiling, fd: int, buf: int):
    data = b"0" * (12 * 8)  # for now, just return 0s
    regreturn = 0

    try:
        ql.mem.write(buf, data)
    except:
        regreturn = -1

    if data:
        ql.log.debug("fstatfs() CONTENT:")
        ql.log.debug(str(data))

    return regreturn

def ql_syscall_statfs(ql: Qiling, path: int, buf: int):
    data = b"0" * (12 * 8)  # for now, just return 0s
    regreturn = 0

    try:
        ql.mem.write(buf, data)
    except:
        regreturn = -1

    return regreturn

def ql_syscall_umask(ql: Qiling, mode: int):
    oldmask = os.umask(mode)

    return oldmask
