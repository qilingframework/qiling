#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
import struct
import sys
import os
import stat
import string
import resource
import socket
import time
import io
import select
import pathlib
import logging

# Remove import fcntl due to Windows Limitation
#import fcntl

from unicorn import *
from unicorn.arm_const import *
from unicorn.x86_const import *
from unicorn.arm64_const import *
from unicorn.mips_const import *

# impport read_string and other commom utils.
from qiling.os.utils import *
from qiling.arch.filetype import *
from qiling.os.linux.thread import *
from qiling.arch.filetype import *
from qiling.os.posix.filestruct import *
from qiling.os.posix.constant import *
from qiling.utils import *

def ql_syscall_exit(ql, null0, null1, null2, null3, null4, null5):
    ql.exit_code = null0
    
    ql.nprint("exit(%u) = %u" % (null0, null0))
    ql.dprint ("[+] is this a child process: ", ql.child_processes)
    
    if ql.child_processes == True:
        os._exit(0)
    
    
    ql.stop(stop_event = THREAD_EVENT_EXIT_EVENT)


def ql_syscall_munmap(ql, munmap_addr , munmap_len, null0, null1, null2, null3):
    munmap_len = ((munmap_len + 0x1000 - 1) // 0x1000) * 0x1000
    ql.uc.mem_unmap(munmap_addr, munmap_len)
    regreturn = 0
    ql.nprint("munmap(0x%x, 0x%x) = %d" % (munmap_addr , munmap_len, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_exit_group(ql, exit_code, null1, null2, null3, null4, null5):
    ql.exit_code = exit_code

    ql.nprint("exit_group(%u)" % ql.exit_code)

    if ql.child_processes == True:
        os._exit(0)

    ql.stop()
    

def ql_syscall_madvise(ql, null0, null1, null2, null3, null4, null5):
    regreturn = 0
    ql.nprint("madvise() = %d" %  regreturn)
    ql_definesyscall_return(ql, regreturn)    


def ql_syscall_sysinfo(ql, sysinfo_info, null0, null1, null2, null3, null4):

    data = b''   
    data += struct.pack("QQQQQQQQQQHQQI",
                       0x1234, # uptime
                       0x2000, # loads (1 min)
                       0x2000, # loads (5 min)
                       0x2000, # loads (15 min)
                       0x10000000, # total ram
                       0x10000000, # free ram
                       0x10000000, # shared memory
                       0x0, # memory used by buffers
                       0x0, # total swap
                       0x0, # free swap
                       0x1, # nb current processes
                       0x0, # total high mem
                       0x0, # available high mem
                       0x1, # memory unit size
    )
    
    regreturn = 0
    ql.nprint("sysinfo(0x%x) = %d" % (sysinfo_info, regreturn))
    #uc.mem_write(sysinfo_info, data)   
    ql_definesyscall_return(ql, regreturn)    


def ql_syscall_alarm(ql, alarm_seconds, null0, null1, null2, null3, null4):
    regreturn = 0
    ql.nprint("alarm(%d) = %d" % (alarm_seconds, regreturn))
    ql_definesyscall_return(ql, regreturn)    


def ql_syscall_issetugid(ql, null0, null1, null2, null3, null4, null5):
    if ql.root == False:
        UGID = 0
    else:    
        UGID = 1000    
    ql.nprint("issetugid(%i)" % UGID)
    regreturn = UGID
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_getuid(ql, null0, null1, null2, null3, null4, null5):
    if ql.root == False:
        UID = 0
    else:    
        UID = 1000
    ql.nprint("getuid(%i)" % UID)
    regreturn = UID
    ql_definesyscall_return(ql, regreturn)    


def ql_syscall_geteuid(ql, null0, null1, null2, null3, null4, null5):
    if ql.root == False:
        EUID = 0
    else:    
        EUID = 1000
    ql.nprint("geteuid(%i)" % EUID)
    regreturn = EUID
    ql_definesyscall_return(ql, regreturn) 


def ql_syscall_getegid(ql, null0, null1, null2, null3, null4, null5):
    if ql.root == False:
        EGID = 0
    else:    
        EGID = 1000
    ql.nprint("getegid(%i)" % EGID)
    regreturn = EGID
    ql_definesyscall_return(ql, regreturn) 


def ql_syscall_getgid(ql, null0, null1, null2, null3, null4, null5):
    if ql.root == False:
        GID = 0
    else:    
        GID = 1000
    ql.nprint("getgid(%i)" % GID)
    regreturn = GID
    ql_definesyscall_return(ql, regreturn)    


def ql_syscall_setgroups(ql, gidsetsize, grouplist, null0, null1, null2, null3):
    if ql.root == False:
        GID = 0
    else:    
        GID = 1000

    regreturn = GID
    ql.nprint("setgroups(0x%x, 0x%x) = %d" % (gidsetsize, grouplist, regreturn))
    ql_definesyscall_return(ql, regreturn)    


def ql_syscall_setgid(ql, null0, null1, null2, null3, null4, null5):
    if ql.root == False:
        GID = 0
    else:    
        GID = 1000
    ql.nprint("setgid(%i)" % GID)
    regreturn = GID
    ql_definesyscall_return(ql, regreturn)           


def ql_syscall_setuid(ql, null0, null1, null2, null3, null4, null5):
    if ql.root == False:
        UID = 0
    else:    
        UID = 1000
    ql.nprint("setuid(%i)" % UID)
    regreturn = UID
    ql_definesyscall_return(ql, regreturn)     


def ql_syscall_faccessat(ql, faccessat_dfd, faccessat_filename, faccessat_mode, null0, null1, null2):

    access_path = ql_read_string(ql, faccessat_filename)
    real_path = ql_transform_to_real_path(ql, access_path)
    relative_path = ql_transform_to_relative_path(ql, access_path)

    regreturn = -1
    if os.path.exists(real_path) == False:
        regreturn = -1
    elif stat.S_ISFIFO(os.stat(real_path).st_mode):
        regreturn = 0
    else:
        regreturn = -1

    ql_definesyscall_return(ql, regreturn)
    ql.nprint("facccessat (%d, 0x%x, 0x%x) = %d" %(faccessat_dfd, faccessat_filename, faccessat_mode, regreturn))
    
    if regreturn == -1:
        ql.dprint("[!] File Not Found or Skipped: %s" % access_path)
    else:
        ql.dprint("[+] File Found: %s" % access_path)


def ql_syscall_open(ql, filename, flags, mode, null0, null1, null2):
    path = ql_read_string(ql, filename)
    real_path = ql_transform_to_real_path(ql, path)
    relative_path = ql_transform_to_relative_path(ql, path)

    flags = flags & 0xffffffff
    mode = mode & 0xffffffff

    for i in range(256):
        if ql.file_des[i] == 0:
            idx = i
            break
    else:
        idx = -1

    if idx == -1:
        regreturn = -1
    else:
        try:
            if ql.arch == QL_ARM:
                mode = 0

            flags = open_flag_mapping(flags, ql)
            ql.file_des[idx] = ql_file.open(real_path, flags, mode)
            regreturn = idx
        except:
            regreturn = -1

    ql.nprint("open(%s, 0x%x, 0x%x) = %d" % (relative_path, flags, mode, regreturn))
    if regreturn >= 0 and regreturn != 2:
        ql.dprint("[+] File Found: %s" % relative_path)
    else:
        ql.dprint("[!] File Not Found %s" % relative_path)
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_openat(ql, openat_fd, openat_path, openat_flags, openat_mode, null0, null1):
    openat_fd = ql.unpacks(ql.pack(openat_fd))
    openat_path = ql_read_string(ql, openat_path)

    real_path = ql_transform_to_real_path(ql, openat_path)
    relative_path = ql_transform_to_relative_path(ql, openat_path)

    openat_flags = openat_flags & 0xffffffff
    openat_mode = openat_mode & 0xffffffff

    for i in range(256):
        if ql.file_des[i] == 0:
            idx = i
            break
    else:
        idx = -1

    if idx == -1:
        regreturn = -1
    else:
        try:
            if ql.arch == QL_ARM:
                mode = 0

            openat_flags = open_flag_mapping(openat_flags, ql)
            ql.file_des[idx] = ql_file.open(real_path, openat_flags, openat_mode)
            regreturn = idx
        except:
            regreturn = -1

    ql.nprint("\nopenat(%d, %s, 0x%x, 0x%x) = %d" % (openat_fd, relative_path, openat_flags, openat_mode, regreturn))
    if regreturn >= 0 and regreturn != 2:
        ql.dprint("[+] File Found: %s" % relative_path)
    else:
        ql.dprint("[!] File Not Found %s" % relative_path)
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_lseek(ql, lseek_fd, lseek_ofset, lseek_origin, null0, null1, null2):
    lseek_ofset = ql.unpacks(ql.pack(lseek_ofset))
    try:
        regreturn = ql.file_des[lseek_fd].lseek(lseek_ofset, lseek_origin)
    except OSError:
        regreturn = -1
    ql.nprint("lseek(%d, 0x%x, 0x%x) = %d" % (lseek_fd, lseek_ofset, lseek_origin, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall__llseek(ql, fd, offset_high, offset_low, result, whence, null0):
    offset = offset_high << 32 | offset_low
    origin = whence
    ret = ql.file_des[fd].lseek(offset, origin)
    regreturn = 0 if ret >= 0 else -1
    if regreturn == 0:
        ql.mem_write(result, ql.pack64(ret))

    ql.nprint("_llseek(%d, 0x%x, 0x%x, 0x%x = %d)" % (fd, offset_high, offset_low, origin, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_brk(ql, brk_input, null0, null1, null2, null3, null4):
    ql.nprint("brk(0x%x)" % brk_input)
    if brk_input != 0:
        if brk_input > ql.brk_address:
            ql.uc.mem_map(ql.brk_address, (int(((brk_input + 0xfff) // 0x1000) * 0x1000 - ql.brk_address)))
            ql.brk_address = int(((brk_input + 0xfff) // 0x1000) * 0x1000)
    else:
        brk_input = ql.brk_address
    ql_definesyscall_return(ql, brk_input)
    ql.dprint("[+] brk return(0x%x)" % ql.brk_address)


def ql_syscall_mprotect(ql, mprotect_start, mprotect_len, mprotect_prot, null0, null1, null2):
    regreturn = 0
    ql.nprint("mprotect(0x%x, 0x%x, 0x%x) = %d" % (mprotect_start, mprotect_len, mprotect_prot, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_uname(ql, address, null0, null1, null2, null3, null4):
    buf = b''
    buf += b'QilingOS'.ljust(65, b'\x00')
    buf += b'ql_vm'.ljust(65, b'\x00')
    buf += b'99.0-RELEASE'.ljust(65, b'\x00')
    buf += b'QiligOS 99.0-RELEASE r1'.ljust(65, b'\x00')
    buf += b'ql_processor'.ljust(65, b'\x00')
    buf += b''.ljust(65, b'\x00')
    ql.uc.mem_write(address, buf)
    regreturn = 0
    ql.nprint("uname(0x%x) = %d" % (address, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_access(ql, access_path, access_mode, null0, null1, null2, null3):
    path = (ql_read_string(ql, access_path))

    real_path = ql_transform_to_real_path(ql, path)
    relative_path = ql_transform_to_relative_path(ql, path)

    if os.path.exists(real_path) == False:
        regreturn = -1
    else:
        regreturn = 0

    ql_definesyscall_return(ql, regreturn)

    ql.nprint("access(%s, 0x%x) = %d " % (relative_path, access_mode, regreturn))
    if regreturn == 0:
        ql.dprint("[+] File found: %s" % relative_path)
    else:
        ql.dprint("[!] No such file or directory")
    

def ql_syscall_mmap(ql, mmap2_addr, mmap2_length, mmap2_prot, mmap2_flags, mmap2_fd, mmap2_pgoffset):
    # this is ugly patch, we might need to get value from elf parse,
    # is32bit or is64bit value not by arch
   
    MAP_ANONYMOUS=32

    if (ql.arch == QL_ARM64) or (ql.arch == QL_X8664):
        mmap2_fd = ql.unpack64(ql.pack64(mmap2_fd))

    elif (ql.arch == QL_MIPS32EL):
        mmap2_fd = ql.unpack32s(ql.uc.mem_read(mmap2_fd, 4))
        mmap2_pgoffset = ql.unpack32(ql.uc.mem_read(mmap2_pgoffset, 4))
        MAP_ANONYMOUS=2048
    else:
        mmap2_fd = ql.unpack32s(ql.pack32(mmap2_fd))


    mmap_base = mmap2_addr
    need_mmap = True

    if mmap2_addr != 0 and mmap2_addr < ql.mmap_start:
        need_mmap = False
    if mmap2_addr == 0:
        mmap_base = ql.mmap_start
        ql.mmap_start = mmap_base + ((mmap2_length + 0x1000 - 1) // 0x1000) * 0x1000

    ql.dprint("[+] log mmap - mmap(0x%x, %d, 0x%x, 0x%x, %d, %d)" % (mmap2_addr, mmap2_length, mmap2_prot, mmap2_flags, mmap2_fd, mmap2_pgoffset))
    ql.dprint("[+] log mmap - return addr : " + hex(mmap_base))
    ql.dprint("[+] log mmap - addr range  : " + hex(mmap_base) + ' - ' + hex(mmap_base + ((mmap2_length + 0x1000 - 1) // 0x1000) * 0x1000))

    if need_mmap:
        ql.dprint("[+] log mmap - mapping needed")
        try:
            ql.uc.mem_map(mmap_base, ((mmap2_length + 0x1000 - 1) // 0x1000) * 0x1000)
        except:
            ql.show_map_info()
            raise   

    ql.uc.mem_write(mmap_base, b'\x00' * (((mmap2_length + 0x1000 - 1) // 0x1000) * 0x1000))
    
    mem_s = mmap_base
    mem_e = mmap_base + ((mmap2_length + 0x1000 - 1) // 0x1000) * 0x1000
    mem_info = ''

    if ((mmap2_flags & MAP_ANONYMOUS) == 0) and mmap2_fd < 256 and ql.file_des[mmap2_fd] != 0:
        ql.file_des[mmap2_fd].lseek(mmap2_pgoffset)
        data = ql.file_des[mmap2_fd].read(mmap2_length)

        ql.dprint("[+] log mem wirte : " + hex(len(data)))
        ql.dprint("[+] log mem mmap  : " + str(ql.file_des[mmap2_fd].name))
        ql.uc.mem_write(mmap_base, data)
        
        mem_info = ql.file_des[mmap2_fd].name
        
    ql.insert_map_info(mem_s, mem_e, mem_info)
    
    if ql.output == QL_OUT_DEFAULT:
        ql.nprint("mmap(0x%x, %d, 0x%x, 0x%x, %d, %d) = 0x%x" % (mmap2_addr, mmap2_length, mmap2_prot, mmap2_flags, mmap2_fd, mmap2_pgoffset, mmap_base))
    
    regreturn = mmap_base
    ql.dprint("[+] mmap_base is 0x%x" % regreturn)

    ql_definesyscall_return(ql, regreturn)


def ql_syscall_mmap2(ql, mmap2_addr, mmap2_length, mmap2_prot, mmap2_flags, mmap2_fd, mmap2_pgoffset):
    # this is ugly patch, we might need to get value from elf parse,
    # is32bit or is64bit value not by arch
   
    MAP_ANONYMOUS=32

    if (ql.arch == QL_ARM64) or (ql.arch == QL_X8664):
        mmap2_fd = ql.unpack64(ql.pack64(mmap2_fd))

    elif (ql.arch == QL_MIPS32EL):
        mmap2_fd = ql.unpack32s(ql.uc.mem_read(mmap2_fd, 4))
        mmap2_pgoffset = ql.unpack32(ql.uc.mem_read(mmap2_pgoffset, 4)) * 4096
        MAP_ANONYMOUS=2048
    else:
        mmap2_fd = ql.unpack32s(ql.pack32(mmap2_fd))
        mmap2_pgoffset = mmap2_pgoffset * 4096


    mmap_base = mmap2_addr
    need_mmap = True

    if mmap2_addr != 0 and mmap2_addr < ql.mmap_start:
        need_mmap = False
    if mmap2_addr == 0:
        mmap_base = ql.mmap_start
        ql.mmap_start = mmap_base + ((mmap2_length + 0x1000 - 1) // 0x1000) * 0x1000

    ql.dprint("[+] log mmap - mmap2(0x%x, %d, 0x%x, 0x%x, %d, %d)" % (mmap2_addr, mmap2_length, mmap2_prot, mmap2_flags, mmap2_fd, mmap2_pgoffset))
    ql.dprint("[+] log mmap - return addr : " + hex(mmap_base))
    ql.dprint("[+] log mmap - addr range  : " + hex(mmap_base) + ' - ' + hex(mmap_base + ((mmap2_length + 0x1000 - 1) // 0x1000) * 0x1000))

    if need_mmap:
        ql.dprint("[+] log mmap - mapping needed")
        try:
            ql.uc.mem_map(mmap_base, ((mmap2_length + 0x1000 - 1) // 0x1000) * 0x1000)
        except:
            ql.show_map_info()
            raise     

    ql.uc.mem_write(mmap_base, b'\x00' * (((mmap2_length + 0x1000 - 1) // 0x1000) * 0x1000))
    
    mem_s = mmap_base
    mem_e = mmap_base + ((mmap2_length + 0x1000 - 1) // 0x1000) * 0x1000
    mem_info = ''

    if ((mmap2_flags & MAP_ANONYMOUS) == 0) and mmap2_fd < 256 and ql.file_des[mmap2_fd] != 0:
        ql.file_des[mmap2_fd].lseek(mmap2_pgoffset)
        data = ql.file_des[mmap2_fd].read(mmap2_length)

        ql.dprint("[+] log mem wirte : " + hex(len(data)))
        ql.dprint("[+] log mem mmap  : " + str(ql.file_des[mmap2_fd].name))
        ql.uc.mem_write(mmap_base, data)
        
        mem_info = ql.file_des[mmap2_fd].name
        
    ql.insert_map_info(mem_s, mem_e, mem_info)
    
    if ql.output == QL_OUT_DEFAULT:
        ql.nprint("mmap2(0x%x, %d, 0x%x, 0x%x, %d, %d) = 0x%x" % (mmap2_addr, mmap2_length, mmap2_prot, mmap2_flags, mmap2_fd, mmap2_pgoffset, mmap_base))
    
    regreturn = mmap_base
    ql.dprint("[+] mmap_base is 0x%x" % regreturn)

    ql_definesyscall_return(ql, regreturn)


def ql_syscall_close(ql, close_fd, null0, null1, null2, null3, null4):
    regreturn = -1
    if close_fd < 256 and ql.file_des[close_fd] != 0:
        ql.file_des[close_fd].close()
        ql.file_des[close_fd] = 0
        regreturn = 0
    ql.nprint("close(%d) = %d" % (close_fd, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_fstatat64(ql, fstatat64_fd, fstatat64_fname, fstatat64_buf, fstatat64_flag, null0, null1):
    fstatat64_fname = ql_read_string(ql, fstatat64_fname)

    real_path = ql_transform_to_real_path(ql, fstatat64_fname)
    relative_path = ql_transform_to_relative_path(ql, fstatat64_fname)

    regreturn = -1
    if os.path.exists(real_path) == True:
        fstat64_info = os.stat(real_path)

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
        ql.uc.mem_write(fstatat64_buf,fstat64_buf)
        regreturn = 0

    ql.nprint("fstatat64(0x%x, %s) = %d" % (fstatat64_fd, relative_path, regreturn))
    if regreturn == 0:
        ql.dprint("[+] Directory Found: %s"  % relative_path)
    else:
        ql.dprint("[!] Directory Not Found: %s"  % relative_path)
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_fstat64(ql, fstat64_fd, fstat64_add, null0, null1, null2, null3):
    if fstat64_fd < 256 and ql.file_des[fstat64_fd] != 0:
        user_fileno = fstat64_fd
        fstat64_info = ql.file_des[user_fileno].fstat()
        
        if ql.arch == QL_ARM64:
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
        else:

            # pack fstatinfo
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

        ql.uc.mem_write(fstat64_add, fstat64_buf)
        regreturn = 0
    else:
        regreturn = -1

    ql.nprint("fstat64(%d, 0x%x) = %d" % (fstat64_fd, fstat64_add, regreturn))
    if regreturn == 0:
        ql.dprint("[+] fstat64 write completed")
    else:
        ql.dprint("[!] fstat64 read/write fail")
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_fstat(ql, fstat_fd, fstat_add, null0, null1, null2, null3):
    
    if fstat_fd < 256 and ql.file_des[fstat_fd] != 0:
        user_fileno = fstat_fd
        fstat_info = ql.file_des[user_fileno].fstat()

        if ql.arch == QL_MIPS32EL:
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
        elif ql.arch == QL_X8664:
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

        ql.uc.mem_write(fstat_add, fstat_buf)
        regreturn = 0        
    else:
        regreturn = -1

    ql.nprint("fstat(%d, 0x%x) = %d" % (fstat_fd, fstat_add, regreturn))
    if regreturn == 0:
        ql.dprint("[+] fstat write completed")
    else:
        ql.dprint("[!] fstat read/write fail")
    ql_definesyscall_return(ql, regreturn)


# int stat64(const char *pathname, struct stat64 *buf);
def ql_syscall_stat64(ql, stat64_pathname, stat64_buf_ptr, null0, null1, null2, null3):
    stat64_file = (ql_read_string(ql, stat64_pathname))

    real_path = ql_transform_to_real_path(ql, stat64_file)
    relative_path = ql_transform_to_relative_path(ql, stat64_file)
    if os.path.exists(real_path) == False:
        regreturn = -1
    else:
        stat64_info = os.stat(real_path)

        if ql.arch == QL_MIPS32EL:
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

        ql.uc.mem_write(stat64_buf_ptr, stat64_buf)
        regreturn = 0

    ql.nprint("stat64(%s, 0x%x) = %d" % (relative_path, stat64_buf_ptr, regreturn))
    if regreturn == 0:
        ql.dprint("[+] stat64 write completed")
    else:
        ql.dprint("[!] stat64 read/write fail")
    ql_definesyscall_return(ql, regreturn)


# int stat(const char *path, struct stat *buf);
def ql_syscall_stat(ql, stat_path, stat_buf_ptr, null0, null1, null2, null3):
    stat_file = (ql_read_string(ql, stat_path))

    real_path = ql_transform_to_real_path(ql, stat_file)
    relative_path = ql_transform_to_relative_path(ql, stat_file)

    if os.path.exists(real_path) == False:
        regreturn = -1
    else:
        stat_info = os.stat(real_path)

        if ql.arch == QL_MIPS32EL:
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
        ql.uc.mem_write(stat_buf_ptr, stat_buf)

    ql.nprint("stat(%s, 0x%x) = %d" % (relative_path, stat_buf_ptr, regreturn))
    if regreturn == 0:
        ql.dprint("[+] stat() write completed")
    else:
        ql.dprint("[!] stat() read/write fail")
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_read(ql, read_fd, read_buf, read_len, null0, null1, null2):
    data = None
    if read_fd < 256 and ql.file_des[read_fd] != 0:
        try:
            data = ql.file_des[read_fd].read(read_len)
            ql.uc.mem_write(read_buf, data)
            regreturn = len(data)
        except:
            regreturn = -1
    else:
        regreturn = -1
    ql.nprint("read(%d, 0x%x, 0x%x) = %d" % (read_fd, read_buf, read_len, regreturn))

    if data:
        ql.dprint("[+] read() CONTENT:")
        ql.dprint(data)
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_write(ql, write_fd, write_buf, write_count, null0, null1, null2):
    regreturn = 0
    buf = None
    
    try:
        buf = ql.uc.mem_read(write_buf, write_count)
        ql.nprint("\nwrite(%d,%x,%i) = %d" % (write_fd, write_buf, write_count, regreturn))
        ql.file_des[write_fd].write(buf)
        regreturn = write_count
    except:
        regreturn = -1
        ql.nprint("write(%d,%x,%i) = %d" % (write_fd, write_buf, write_count, regreturn))
        if ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
            raise
    #ql.nprint("write(%d,%x,%i) = %d" % (write_fd, write_buf, write_count, regreturn))
    #if buf:
    #    ql.nprint(buf.decode(errors='ignore'))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_writev(ql, writev_fd, writev_vec, writev_vien, null0, null1, null2):
    regreturn = 0
    size_t_len = ql.archbit // 8
    iov = ql.uc.mem_read(writev_vec, writev_vien * size_t_len * 2)
    ql.nprint("writev(0x%x, 0x%x, 0x%x)" % (writev_fd, writev_vec, writev_vien))
    for i in range(writev_vien):
        addr = ql.unpack(iov[i * size_t_len * 2 : i * size_t_len * 2 + size_t_len])
        l = ql.unpack(iov[i * size_t_len * 2 + size_t_len : i * size_t_len * 2 + size_t_len * 2])
        ql.nprint("[+] writev() CONTENT : %s" % str(ql.uc.mem_read(addr, l)))
    ql_definesyscall_return(ql, regreturn)    
    

def ql_syscall_archprctl(ql, null0, ARCH_SET_FS, null1, null2, null3, null4):
    FSMSR = 0xC0000100
    ql.uc.msr_write(FSMSR, ARCH_SET_FS)
    regreturn = 0
    ql.nprint("archprctl(0x%x) = %d" % (ARCH_SET_FS, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_prctl(ql, null0, null1, null2, null3, null4, null5):
    regreturn = 0
    ql.nprint("prctl() = %d" % (regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_readlink(ql, path_name, path_buff, path_buffsize, null0, null1, null2):
    pathname = (ql.uc.mem_read(path_name, 0x100).split(b'\x00'))[0]
    pathname = str(pathname, 'utf-8', errors="ignore")

    real_path = ql_transform_to_link_path(ql, pathname)
    relative_path = ql_transform_to_relative_path(ql, pathname)

    if os.path.exists(real_path) == False:
        regreturn = -1
    elif relative_path == '/proc/self/exe':
        FILEPATH = ql.path
        localpath = os.path.abspath(FILEPATH)
        localpath = bytes(localpath, 'utf-8') + b'\x00'
        ql.uc.mem_write(path_buff, localpath)
        regreturn = (len(localpath)-1)
    else:
        regreturn = 0x0    
    
    ql.nprint("readlink(%s, 0x%x, 0x%x) = %d" % (relative_path, path_buff, path_buffsize, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_getcwd(ql, path_buff, path_buffsize, null0, null1, null2, null3):
    localpath = ql_transform_to_relative_path(ql, './')
    localpath = bytes(localpath, 'utf-8') + b'\x00'
    ql.uc.mem_write(path_buff, localpath)
    regreturn = (len(localpath))

    pathname = (ql.uc.mem_read(path_buff, 0x100).split(b'\x00'))[0]
    pathname = str(pathname, 'utf-8', errors="ignore")

    ql.nprint("getcwd(%s, 0x%x) = %d" % (pathname, path_buffsize, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_chdir(ql, path_name, null0, null1, null2, null3, null4):
    regreturn = 0
    pathname = ql_read_string(ql, path_name)

    real_path = ql_transform_to_real_path(ql, pathname)
    relative_path = ql_transform_to_relative_path(ql, pathname)

    if os.path.exists(real_path) and os.path.isdir(real_path):
        if ql.thread_management != None:
            pass
        else:
            ql.current_path = relative_path + '/'
        ql.nprint("chdir(%s) = %d"% (relative_path, regreturn))
    else:
        regreturn = -1    
        ql.nprint("chdir(%s) = %d : Not Found" % (relative_path, regreturn))
    ql_definesyscall_return(ql, regreturn)     


def ql_syscall_readlinkat(ql, readlinkat_dfd, readlinkat_path, readlinkat_buf, readlinkat_bufsiz, null0, null1):
    pathname = (ql.uc.mem_read(readlinkat_path, 0x100).split(b'\x00'))[0]
    pathname = str(pathname, 'utf-8', errors="ignore")

    real_path = ql_transform_to_link_path(ql, pathname)
    relative_path = ql_transform_to_relative_path(ql, pathname)

    if os.path.exists(real_path) == False:
        regreturn = -1
    elif relative_path == '/proc/self/exe':
        FILEPATH = ql.path
        localpath = os.path.abspath(FILEPATH)
        localpath = bytes(localpath, 'utf-8') + b'\x00'
        ql.uc.mem_write(readlinkat_buf, localpath)
        regreturn = (len(localpath)-1)
    else:
        regreturn = 0x0

    ql.nprint("readlinkat(0x%x, 0x%x, 0x%x, 0x%x) = %d" % (readlinkat_dfd, readlinkat_path, readlinkat_buf, readlinkat_bufsiz, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_ugetrlimit(ql, ugetrlimit_resource, ugetrlimit_rlim, null0, null1, null2, null3):
    rlim = resource.getrlimit(ugetrlimit_resource)
    ql.uc.mem_write(ugetrlimit_rlim, ql.pack32s(rlim[0]) + ql.pack32s(rlim[1]))
    regreturn = 0
    ql.nprint("ugetrlimit(%d, 0x%x) = %d" % (ugetrlimit_resource, ugetrlimit_rlim, regreturn))
    ql_definesyscall_return(ql, regreturn)



def ql_syscall_setrlimit(ql, setrlimit_resource, setrlimit_rlim, null0, null1, null2, null3):
    # maybe we can nop the setrlimit
    tmp_rlim = (ql.unpack32s(ql.uc.mem_read(setrlimit_rlim, 4)), ql.unpack32s(ql.uc.mem_read(setrlimit_rlim + 4, 4)))
    resource.setrlimit(setrlimit_resource, tmp_rlim)

    regreturn = 0
    ql.nprint("setrlimit(%d, 0x%x) = %d" % (setrlimit_resource, setrlimit_rlim, regreturn))
    ql_definesyscall_return(ql, regreturn)

def ql_syscall_prlimit64(ql, pid, resource, new_limit, old_limit, null0, null1):
    # setrlimit() and getrlimit()
    #if pid == 0:
    #    ql_syscall_setrlimit(ql, resource, new_limit, 0, 0, 0, 0);
    #    ql_syscall_ugetrlimit(ql, resource, old_limit, 0, 0, 0, 0);
    #    regreturn = 0;
    #else:
        # set other process which pid != 0
    #    regreturn = 0
    regreturn = 0
    #ql.nprint("prlimit64(%d, %d, 0x%x, 0x%x) = %d" % (pid, resource, new_limit, old_limit, regreturn))
    ql_definesyscall_return(ql, regreturn)

def ql_syscall_rt_sigaction(ql, rt_sigaction_signum, rt_sigaction_act, rt_sigaction_oldact, null0, null1, null2):
    if rt_sigaction_oldact != 0:
        if ql.sigaction_act[rt_sigaction_signum] == 0:
            ql.uc.mem_write(rt_sigaction_oldact, b'\x00' * 20)
        else:
            data = b''
            for key in ql.sigaction_act[rt_sigaction_signum]:
                data += ql.pack32(key)
            ql.uc.mem_write(rt_sigaction_oldact, data)

    if rt_sigaction_act != 0:
        data = []
        for key in range(5):
            data.append(ql.unpack32(ql.uc.mem_read(rt_sigaction_act + 4 * key, 4)))
        ql.sigaction_act[rt_sigaction_signum] = data

    regreturn = 0
    ql.nprint("rt_sigaction(0x%x, 0x%x, = 0x%x) = %d" % (rt_sigaction_signum, rt_sigaction_act, rt_sigaction_oldact, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_ioctl(ql, ioctl_fd, ioctl_cmd, ioctl_arg, null0, null1, null2):
    TCGETS = 0x5401
    TIOCGWINSZ = 0x5413
    TIOCSWINSZ = 0x5414
    TCSETSW = 0x5403

    SIOCGIFADDR = 0x8915
    SIOCGIFNETMASK = 0x891b

    
    def ioctl(fd, cmd, arg):
    # Stub for 'ioctl' syscall
    # Return the list of element to pack back depending on target ioctl
    #If the ioctl is disallowed, return False

        ioctl_allowed = None # list of (fd, cmd), None value for wildcard
        ioctl_disallowed = None # list of (fd, cmd), None value for wildcard

        ioctl_allowed = [
        (0, TCGETS),
        (0, TIOCGWINSZ),
        (0, TIOCSWINSZ),
        (1, TCGETS),
        (1, TIOCGWINSZ),
        (1, TIOCSWINSZ),
        ]

        ioctl_disallowed = [
        (2, TCGETS),
        (0, TCSETSW),
        ]

        allowed = False
        disallowed = False

        for test in [(fd, cmd), (None, cmd), (fd, None)]:
            if test in ioctl_allowed:
                allowed = True
            if test in ioctl_disallowed:
                disallowed = True
        if allowed and disallowed:
            raise ValueError("fd: %x, cmd: %x is allowed and disallowed" % (fd, cmd))

        if allowed:

            if cmd == TCGETS:
                return 0, 0, 0, 0
            elif cmd == TIOCGWINSZ:
            # struct winsize
            # {
            #   unsigned short ws_row;	/* rows, in characters */
            #   unsigned short ws_col;	/* columns, in characters */
            #   unsigned short ws_xpixel;	/* horizontal size, pixels */
            #   unsigned short ws_ypixel;	/* vertical size, pixels */
            # };
                return 1000, 360, 1000, 1000
            elif cmd == TIOCSWINSZ:
                # Ignore it
                return
            else:
                raise RuntimeError("Not implemented")
        elif disallowed:
            return False
        else:
            raise KeyError("Unknown ioctl fd:%x cmd:%x" % (fd, cmd))

    if isinstance(ql.file_des[ioctl_fd], ql_socket) and (ioctl_cmd == SIOCGIFADDR or ioctl_cmd == SIOCGIFNETMASK):
        try:
            tmp_arg = ql.uc.mem_read(ioctl_arg, 64)
            ql.dprint("[+] query network card : %s" % tmp_arg)
            data = ql.file_des[ioctl_fd].ioctl(ioctl_cmd, bytes(tmp_arg))
            ql.uc.mem_write(ioctl_arg, data)
            regreturn = 0
        except:
            regreturn = -1
    else:
        try:
            info = ioctl(ioctl_fd, ioctl_cmd, ioctl_arg)
            if ioctl_cmd == TCGETS:
                data = struct.pack("BBBB", *info)
                ql.uc.mem_write(ioctl_arg, data)
            elif ioctl_cmd == TIOCGWINSZ:
                data = struct.pack("HHHH", *info)
                ql.uc.mem_write(ioctl_arg, data)
            else:
                return
            regreturn = 0
        except :
            regreturn = -1

    ql.nprint("ioctl(0x%x, 0x%x, 0x%x) = %d" % (ioctl_fd, ioctl_cmd, ioctl_arg, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_getpid(ql, null0, null1, null2, null3, null4, null5):
    regreturn= 0x512
    ql.nprint("getpid() = ", regreturn)
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_getppid(ql, null0, null1, null2, null3, null4, null5):
    regreturn= 0x1024
    ql.nprint("getpid() = ", regreturn)
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_rt_sigprocmask(ql, rt_sigprocmask_how, rt_sigprocmask_nset, rt_sigprocmask_oset, rt_sigprocmask_sigsetsize, null0, null1):
    SIG_BLOCK = 0x0
    SIG_UNBLOCK = 0x1

    if rt_sigprocmask_how == SIG_BLOCK:
        pass

    regreturn = 0
    ql.nprint("rt_sigprocmask(0x%x, 0x%x, 0x%x, 0x%x) = %d" % (rt_sigprocmask_how, rt_sigprocmask_nset, rt_sigprocmask_oset, rt_sigprocmask_sigsetsize, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_vfork(ql, null0, null1, null2, null3, null4, null5):
    pid = os.fork()

    if pid == 0:
        ql.child_processes = True
        ql.dprint ("[+] vfork(): is this a child process: ", ql.child_processes)
        regreturn = 0
        if ql.thread_management != None:
            ql.thread_management.cur_thread.set_thread_log_file(ql.log_file)
        else:
            if ql.log_file != None:
                ql.log_file_fd = open(ql.log_file + "_" + str(os.getpid()), 'w+')
                #ql.log_file_fd = logging.basicConfig(filename=ql.log_file_name + "_" + str(os.getpid()) + ".qlog", filemode='w+', level=logging.DEBUG, format='%(message)s')
    else:
        regreturn = pid

    if ql.thread_management != None:
        ql.uc.emu_stop()

    ql.nprint("vfork() = %d" % regreturn)
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_setsid(ql, null0, null1, null2, null3, null4, null5):
    regreturn = os.getpid()
    ql.nprint("setsid() = %d" % regreturn)
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_time(ql, null0, null1, null2, null3, null4, null5):
    regreturn = int(time.time()) 
    ql.nprint("time() = %d" % regreturn)
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_wait4(ql, wait4_pid, wait4_wstatus, wait4_options, wait4_rusage, null0, null1):
    spid, status, rusage = os.wait4(wait4_pid, wait4_options)
    ql.uc.mem_write(wait4_wstatus, ql.pack32(status))
    regreturn = spid
    ql.nprint("wait4(%d, %d) = %d"% (wait4_pid, wait4_options, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_execve(ql, execve_pathname, execve_argv, execve_envp, null0, null1, null2):
    pathname = ql_read_string(ql, execve_pathname)
    real_path = ql_transform_to_real_path(ql, pathname)
    relative_path = ql_transform_to_relative_path(ql, pathname)

    word_size = 8 if (ql.arch == QL_ARM64) or (ql.arch == QL_X8664) else 4
    unpack = ql.unpack64 if (ql.arch == QL_ARM64) or (ql.arch == QL_X8664) else ql.unpack32

    argv = []
    if execve_argv != 0:
        while True:
            argv_addr = unpack(ql.uc.mem_read(execve_argv, word_size))
            if argv_addr == 0:
                break
            argv.append(ql_read_string(ql, argv_addr))
            execve_argv += word_size

    env = {}
    if execve_envp != 0:
        while True:
            env_addr = unpack(ql.uc.mem_read(execve_envp, word_size))
            if env_addr == 0:
                break
            env_str = ql_read_string(ql, env_addr)
            idx = env_str.index('=')
            key = env_str[ : idx]
            val = env_str[idx + 1 : ]
            env[key] = val
            execve_envp += word_size

    ql.uc.emu_stop()

    if ql.shellcoder:
        pass
    else:
        ql.stack_address    = 0
        ql.argv             = argv
        ql.env              = env
        ql.path             = real_path
        ql.map_info         = []
        ql.runtype          = ql_get_os_module_function(ql.ostype, ql.arch, "runner")
        loader_file         = ql_get_os_module_function(ql.ostype, ql.arch, "loader_file")
        
        loader_file(ql)
        ql.run()
    
    ql.nprint("execve(%s, [%s], [%s])"% (pathname, ', '.join(argv), ', '.join([key + '=' + value for key, value in env.items()])))    


def ql_syscall_socket(ql, socket_domain, socket_type, socket_protocol, null0, null1, null2):
    if ql.arch == QL_MIPS32EL and socket_type == 2:
        socket_type = 1
    elif ql.arch == QL_MIPS32EL and socket_type == 1:
        socket_type = 1   

    idx = -1
    for i in range(256):
        if ql.file_des[i] == 0:
            idx = i
            break
    try:
        if idx == -1:
            regreturn = -1
        else:
            ql.file_des[idx] = ql_socket.open(socket_domain, socket_type, socket_protocol)
            regreturn = (idx)
    except:
        regreturn = -1
    
    ql.nprint("socket(%d, %d, %d) = %d" % (socket_domain, socket_type, socket_protocol, regreturn))
    socket_type = socket_type_mapping(socket_type, ql.arch)
    socket_domain = socket_domain_mapping(socket_domain, ql.arch)
    ql.dprint("[+] scoket(%s, %s, %s) = %d" % (socket_domain, socket_type, socket_protocol, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_connect(ql, connect_sockfd, connect_addr, connect_addrlen, null0, null1, null2):  
    AF_UNIX = 1
    AF_INET = 2
    sock_addr = ql.uc.mem_read(connect_addr, connect_addrlen)
    family = ql.unpack16(sock_addr[ : 2])
    s = ql.file_des[connect_sockfd]
    ip = b''
    sun_path = b''
    port = 0
    try:
        if s.family == family:
            if s.family == AF_UNIX:                
                sun_path = sock_addr[2 : ].split(b"\x00")[0]
                sun_path = ql_transform_to_real_path(ql, sun_path.decode())
                s.connect(sun_path) 
                regreturn = 0
            elif s.family == AF_INET:
                port, host = struct.unpack(">HI", sock_addr[2:8])
                ip = ql_bin_to_ip(host)
                s.connect((ip, port))
                regreturn = 0 
            else:
                regreturn = -1
        else:
            regreturn = -1
    except:
        regreturn = -1
    
    if s.family == AF_UNIX:
        ql.nprint("connect(%s) = %d" % (sun_path, regreturn))
    elif s.family == AF_INET:
        ql.nprint("connect(%s, %d) = %d" % (ip, port, regreturn))
    else:
        ql.nprint("connect() = %d" % (regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_setsockopt(ql, null0, null1, null2, null3, null4, null5):
    ql.nprint("setsockopt")
    regreturn = 0
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_dup2(ql, dup2_oldfd, dup2_newfd, null0, null1, null2, null3):
    if 0 <= dup2_newfd < 256 and 0 <= dup2_oldfd < 256:
        if ql.file_des[dup2_oldfd] != 0:
            ql.file_des[dup2_newfd] = ql.file_des[dup2_oldfd].dup()
            regreturn = dup2_newfd
        else:
            regreturn = -1
    else:
        regreturn = -1
    ql.nprint("dup2(%d, %d) = %d" % (dup2_oldfd, dup2_newfd, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_dup3(ql, null0, null1, null2, null3, null4, null5):
    ql.nprint("dup3")
    regreturn = 0
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_fcntl(ql, fcntl_fd, fcntl_cmd, null0, null1, null2, null3):
    F_SETFD = 2
    F_GETFL = 3
    F_SETFL = 4
    regreturn = 0
    if fcntl_cmd == F_SETFD:
        regreturn = 0
    elif fcntl_cmd == F_GETFL:
        regreturn = 2
    elif fcntl_cmd == F_SETFL:
        regreturn = 0

    ql.nprint("fcntl(%d, %d) = %d" % (fcntl_fd, fcntl_cmd, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_fcntl64(ql, fcntl_fd, fcntl_cmd, fcntl_arg, null1, null2, null3):
    
    F_GETFD = 1
    F_SETFD = 2
    F_GETFL = 3
    F_SETFL = 4

    if fcntl_cmd == F_GETFL:
        regreturn = 2
    elif fcntl_cmd == F_SETFL:
        regreturn = 0
    elif fcntl_cmd == F_GETFD:
        regreturn = 2
    elif fcntl_cmd == F_SETFD:
        regreturn = 0
    else:
        regreturn = 0    

    ql.nprint("fcntl64(%d, %d, %d) = %d" % (fcntl_fd, fcntl_cmd, fcntl_arg, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_shutdown(ql, shutdown_fd, shutdown_how, null0, null1, null2, null3):
    ql.nprint("shutdown(%d, %d)" % (shutdown_fd, shutdown_how))
    if shutdown_fd >=0 and shutdown_fd < 256 and ql.file_des[shutdown_fd] != 0:
        try:
            ql.file_des[shutdown_fd].shutdown(shutdown_how)
            regreturn = 0
        except:
            regreturn = -1
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_bind(ql, bind_fd, bind_addr, bind_addrlen,  null0, null1, null2):
    regreturn = 0

    if ql.arch == QL_X8664:
        data = ql.uc.mem_read(bind_addr, 8)
    else:
        data = ql.uc.mem_read(bind_addr, bind_addrlen)

    sin_family, = struct.unpack("<h", data[:2])
    port, host = struct.unpack(">HI", data[2:8])
    host = ql_bin_to_ip(host)
    
    if ql.root == False and port <= 1024:
        port = port + 8000    

    if sin_family == 1:
        path = data[2 : ].split(b'\x00')[0]
        path = ql_transform_to_real_path(ql, path.decode())
        ql.nprint(path)
        ql.file_des[bind_fd].bind(path)

    # need a proper fix, for now ipv4 comes first
    elif sin_family == 2 and ql.bindtolocalhost == True:
        ql.file_des[bind_fd].bind(('127.0.0.1', port))
        host = "127.0.0.1"
 
    # IPv4 should comes first
    elif ql.ipv6 == True and sin_family == 10 and ql.bindtolocalhost == True:
        ql.file_des[bind_fd].bind(('::1', port))
        host = "::1"
    
    elif ql.bindtolocalhost == False:
         ql.file_des[bind_fd].bind((host, port))
    
    else:
        regreturn = -1       

    if ql.shellcoder:
        regreturn = 0

    if sin_family == 1:
        ql.nprint("bind(%d, %s, %d) = %d" % (bind_fd, path, bind_addrlen, regreturn))
    else:
        ql.nprint("bind(%d,%s:%d,%d) = %d" % (bind_fd, host, port, bind_addrlen,regreturn))
        ql.dprint ("[+] syscall bind host: %s and port: %i sin_family: %i" % (ql_bin_to_ip(host), port, sin_family))

    ql_definesyscall_return(ql, regreturn)    


def ql_syscall_listen(ql, listen_sockfd, listen_backlog, null0, null1, null2, null3):
    if listen_sockfd < 256 and ql.file_des[listen_sockfd] != 0:
        try:
            ql.file_des[listen_sockfd].listen(listen_backlog)
            regreturn = 0
        except:
            if ql.output == QL_OUT_DEBUG:
                raise            
            regreturn = -1
    else:
        regreturn = -1
    ql.nprint("listen(%d, %d) = %d" % (listen_sockfd, listen_backlog, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_nanosleep(ql, nanosleep_req, nanosleep_rem, null0, null1, null2, null3):
    def nanosleep_block_fuc(ql, th, arg):
        st, tm = arg
        et = ql.thread_management.runing_time
        if et - st >= tm:
            return False
        else:
            return True

    tv_sec = ql.unpack32(ql.uc.mem_read(nanosleep_req, 4))
    tv_sec += ql.unpack(ql.uc.mem_read(nanosleep_req + 4, 4)) / 1000000000
    if ql.thread_management == None:
        time.sleep(tv_sec)
    else:
        ql.uc.emu_stop()

        th = ql.thread_management.cur_thread
        th.blocking()
        th.set_blocking_condition(nanosleep_block_fuc, [ql.thread_management.runing_time, int(tv_sec * 1000000)])

    regreturn = 0
    ql.nprint("nanosleep(0x%x, 0x%x) = %d" % (nanosleep_req, nanosleep_rem, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_setitimer(ql, setitimer_which, setitimer_new_value, setitimer_old_value, null0, null1, null2):
    # TODO:The system provides each process with three interval timers, each decrementing in a distinct time domain. 
    # When any timer expires, a signal is sent to the process, and the timer (potentially) restarts.
    # But I haven’t figured out how to send a signal yet.
    regreturn = 0
    ql.nprint("setitimer(%d, %x, %x) = %d" % (setitimer_which, setitimer_new_value, setitimer_old_value, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall__newselect(ql, _newselect_nfds, _newselect_readfds, _newselect_writefds, _newselect_exceptfds, _newselect_timeout, null0):
    
    regreturn = 0
    
    def parse_fd_set(ql, max_fd, struct_addr):
        fd_list = []
        fd_map = {}
        idx = 0
        tmp = 0
        if struct_addr == 0:
            return fd_list, fd_map
        while idx < max_fd:
            if idx % 32 == 0:
                tmp = ql.unpack32(ql.uc.mem_read(struct_addr + idx, 4))
            if tmp & 0x1 != 0:
                fd_list.append(ql.file_des[idx].socket)
                fd_map[ql.file_des[idx].socket] = idx
            tmp = tmp >> 1
            idx += 1
        return fd_list, fd_map

    def set_fd_set(buf, idx):
        buf = buf[ : idx // 8] + bytes([buf[idx // 8] | (0x1 << (idx % 8))]) + buf[idx // 8 + 1 : ]
        return buf

    tmp_r_fd, tmp_r_map = parse_fd_set(ql, _newselect_nfds, _newselect_readfds)
    tmp_w_fd, tmp_w_map = parse_fd_set(ql, _newselect_nfds, _newselect_writefds)
    tmp_e_fd, tmp_e_map = parse_fd_set(ql, _newselect_nfds, _newselect_exceptfds)

    timeout = ql.unpack32(ql.uc.mem_read(_newselect_timeout, 4))
    try:
        ans = select.select(tmp_r_fd, tmp_w_fd, tmp_e_fd, timeout)
        regreturn = len(ans[0]) + len(ans[1]) + len(ans[2])

        if _newselect_readfds != 0:
            tmp_buf = b'\x00' * (_newselect_nfds // 8 + 1)
            for i in ans[0]:
                ql.dprint("debug : " + str(tmp_r_map[i]))
                tmp_buf = set_fd_set(tmp_buf, tmp_r_map[i])
            ql.uc.mem_write(_newselect_readfds, tmp_buf)

        if _newselect_writefds != 0:
            tmp_buf = b'\x00' * (_newselect_nfds // 8 + 1)
            for i in ans[1]:
                tmp_buf = set_fd_set(tmp_buf, tmp_w_map[i])
            ql.uc.mem_write(_newselect_writefds, tmp_buf)

        if _newselect_exceptfds != 0:
            tmp_buf = b'\x00' * (_newselect_nfds // 8 + 1)
            for i in ans[2]:
                tmp_buf = set_fd_set(tmp_buf, tmp_e_map[i])
            ql.uc.mem_write(_newselect_exceptfds, tmp_buf)
    except:
        if ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
            raise
    ql.nprint("_newselect(%d, %x, %x, %x, %x) = %d" % (_newselect_nfds, _newselect_readfds, _newselect_writefds, _newselect_exceptfds, _newselect_timeout, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_accept(ql, accept_sockfd, accept_addr, accept_addrlen, null0, null1, null2):    
    def inet_addr(ip):
        ret = b''
        tmp = ip.split('.')
        if len(tmp) != 4:
            return ret
        for i in tmp[ : : -1]:
            ret += bytes([int(i)])
        return ret
    try:
        conn, address = ql.file_des[accept_sockfd].accept()
        idx = -1
        for i in range(256):
            if ql.file_des[i] == 0:
                idx = i
                break
        if idx == -1:
            regreturn = -1
        else:
            ql.file_des[idx] = conn
            regreturn = idx

        if ql.shellcoder == None:    
            tmp_buf = ql.pack16(conn.family)
            tmp_buf += ql.pack16(address[1])
            tmp_buf += inet_addr(address[0])
            tmp_buf += b'\x00' * 8
            ql.uc.mem_write(accept_addr, tmp_buf)
            ql.uc.mem_write(accept_addrlen, ql.pack32(16))
    except:
        if ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
            raise
        regreturn = -1
    ql.nprint("accep(%d, %x, %x) = %d" %(accept_sockfd, accept_addr, accept_addrlen, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_times(ql, times_tbuf, null0, null1, null2, null3, null4):
    tmp_times = os.times()
    if times_tbuf != 0:
        tmp_buf = b''
        tmp_buf += ql.pack32(int(tmp_times.user * 1000))
        tmp_buf += ql.pack32(int(tmp_times.system * 1000))
        tmp_buf += ql.pack32(int(tmp_times.children_user * 1000))
        tmp_buf += ql.pack32(int(tmp_times.children_sytem * 1000))
        ql.uc.mem_write(times_tbuf, tmp_buf)
    regreturn = int(tmp_times.elapsed * 100)
    ql.nprint('times(%x) = %d' % (times_tbuf, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_gettimeofday(ql, gettimeofday_tv, gettimeofday_tz, null0, null1, null2, null3):
    tmp_time = time.time()
    tv_sec = int(tmp_time)
    tv_usec = int((tmp_time - tv_sec) * 1000000)

    if gettimeofday_tv != 0:
        ql.uc.mem_write(gettimeofday_tv, ql.pack32(tv_sec) + ql.pack32(tv_usec))
    if gettimeofday_tz != 0:
        ql.uc.mem_write(gettimeofday_tz, b'\x00' * 8)
    regreturn = 0
    ql.nprint("gettimeofday(%x, %x) = %d" % (gettimeofday_tv, gettimeofday_tz, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_recv(ql, recv_sockfd, recv_buf, recv_len, recv_flags, null0, null1):
    if recv_sockfd < 256 and ql.file_des[recv_sockfd] != 0:
        tmp_buf = ql.file_des[recv_sockfd].recv(recv_len, recv_flags)
        ql.uc.mem_write(recv_buf, tmp_buf)
        regreturn = len(tmp_buf)
    else:
        regreturn = -1
    ql.nprint("recv(%d, %x, %d, %x) = %d" % (recv_sockfd, recv_buf, recv_len, recv_flags, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_send(ql, send_sockfd, send_buf, send_len, send_flags, null0, null1):
    regreturn = 0
    if send_sockfd < 256 and ql.file_des[send_sockfd] != 0:
        try:
            ql.dprint("debug send start")
            tmp_buf = ql.uc.mem_read(send_buf, send_len)
            ql.dprint(ql.file_des[send_sockfd])
            ql.dprint('fd is ' + str(send_sockfd))
            ql.dprint(tmp_buf)
            ql.dprint("send flag is " + str(send_flags))
            ql.dprint("send len is " + str(send_len))
            ql.file_des[send_sockfd].send(bytes(tmp_buf), send_flags)
            ql.dprint(ql.file_des[send_sockfd])
            regreturn = send_len
            ql.dprint("debug send end")
        except:
            print(sys.exc_info()[0])
            if ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
                raise
    else:
        regreturn = -1
    ql.nprint("send(%d, %x, %d, %x) = %d" % (send_sockfd, send_buf, send_len, send_flags, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_socketcall(ql, socketcall_call, socketcall_args, null0, null1, null2, null3):
    SOCKETCALL_SYS_SOCKET = 1
    SOCKETCALL_SYS_BIND = 2
    SOCKETCALL_SYS_CONNECT = 3
    SOCKETCALL_SYS_LISTEN = 4
    SOCKETCALL_SYS_ACCEPT = 5
    SOCKETCALL_SYS_GETSOCKNAME = 6 
    SOCKETCALL_SYS_GETPEERNAME = 7
    SOCKETCALL_SYS_SOCKETPAIR = 8
    SOCKETCALL_SYS_SEND = 9
    SOCKETCALL_SYS_RECV = 10
    SOCKETCALL_SYS_SENDTO = 11
    SOCKETCALL_SYS_RECVFROM = 12
    SOCKETCALL_SYS_SHUTDOWN = 13
    SOCKETCALL_SYS_SETSOCKOPT = 14
    SOCKETCALL_SYS_GETSOCKOPT = 15
    SOCKETCALL_SYS_SENDMSG = 16
    SOCKETCALL_SYS_RECVMSG = 17
    SOCKETCALL_SYS_ACCEPT4 = 18
    SOCKETCALL_SYS_RECVMMSG = 19
    SOCKETCALL_SYS_SENDMMSG = 20

    ql.print("socketcall(%d, %x)" % (socketcall_call, socketcall_args))

    if socketcall_call == SOCKETCALL_SYS_SOCKET:
        socketcall_domain = ql.unpack(ql.uc.mem_read(socketcall_args, ql.byte))
        socketcall_type = ql.unpack(ql.uc.mem_read(socketcall_args + ql.byte, ql.byte))
        socketcall_protocol = ql.unpack(ql.uc.mem_read(socketcall_args + ql.byte * 2, ql.byte))
        ql_syscall_socket(ql, socketcall_domain, socketcall_type, socketcall_protocol, 0, 0, 0)
    elif socketcall_call == SOCKETCALL_SYS_CONNECT:
        socketcall_sockfd = ql.unpack(ql.uc.mem_read(socketcall_args, ql.byte))
        socketcall_addr = ql.unpack(ql.uc.mem_read(socketcall_args + ql.byte, ql.byte))
        socketcall_addrlen = ql.unpack(ql.uc.mem_read(socketcall_args + ql.byte * 2, ql.byte))
        ql_syscall_connect(ql, socketcall_sockfd, socketcall_addr, socketcall_addrlen, 0, 0, 0)
    elif socketcall_call == SOCKETCALL_SYS_RECV:
        socketcall_sockfd = ql.unpack(ql.uc.mem_read(socketcall_args, ql.byte))
        socketcall_buf = ql.unpack(ql.uc.mem_read(socketcall_args + ql.byte, ql.byte))
        socketcall_len = ql.unpack(ql.uc.mem_read(socketcall_args + ql.byte * 2, ql.byte))
        socketcall_flags = ql.unpack(ql.uc.mem_read(socketcall_args + ql.byte * 3, ql.byte))
        ql_syscall_recv(ql, socketcall_sockfd, socketcall_buf, socketcall_len, socketcall_flags, 0, 0)
    else:
        ql.dprint("[!] error call %d" % socketcall_call)
        ql.stop(stop_event = THREAD_EVENT_UNEXECPT_EVENT)


def ql_syscall_clone(ql, clone_flags, clone_child_stack, clone_parent_tidptr, clone_newtls, clone_child_tidptr, null0):
    CSIGNAL = 0x000000ff	
    CLONE_VM = 0x00000100	
    CLONE_FS = 0x00000200	
    CLONE_FILES = 0x00000400	
    CLONE_SIGHAND = 0x00000800	
    CLONE_PIDFD = 0x00001000	
    CLONE_PTRACE = 0x00002000	
    CLONE_VFORK = 0x00004000	
    CLONE_PARENT = 0x00008000	
    CLONE_THREAD = 0x00010000	
    CLONE_NEWNS = 0x00020000	
    CLONE_SYSVSEM = 0x00040000	
    CLONE_SETTLS = 0x00080000	
    CLONE_PARENT_SETTID = 0x00100000	
    CLONE_CHILD_CLEARTID = 0x00200000	
    CLONE_DETACHED = 0x00400000	
    CLONE_UNTRACED = 0x00800000	
    CLONE_CHILD_SETTID = 0x01000000	
    CLONE_NEWCGROUP = 0x02000000	
    CLONE_NEWUTS = 0x04000000	
    CLONE_NEWIPC = 0x08000000	
    CLONE_NEWUSER = 0x10000000	
    CLONE_NEWPID = 0x20000000	
    CLONE_NEWNET = 0x40000000	
    CLONE_IO = 0x80000000

    f_th = ql.thread_management.cur_thread	
    newtls = None
    set_child_tid_addr = None

    # Shared virtual memory
    if clone_flags & CLONE_VM != CLONE_VM:
        pid = os.fork()
        if pid != 0:
            regreturn = pid
            ql.nprint("clone(new_stack = %x, flags = %x, tls = %x, ptidptr = %x, ctidptr = %x) = %d" % (clone_child_stack, clone_flags, clone_newtls, clone_parent_tidptr, clone_child_tidptr, regreturn))
            ql_definesyscall_return(ql, regreturn)
        else:
            ql.child_processes = True

            f_th.update_global_thread_id()
            f_th.new_thread_id()
            f_th.set_thread_log_file(ql.log_file)

            if clone_flags & CLONE_SETTLS == CLONE_SETTLS:
                if ql.arch == QL_X86:
                    newtls = ql.uc.mem_read(clone_newtls, 4 * 3)
                else:
                    newtls = clone_newtls
                f_th.set_special_settings_arg(newtls)

            if clone_flags & CLONE_CHILD_CLEARTID == CLONE_CHILD_CLEARTID:
                f_th.set_clear_child_tid_addr(clone_child_tidptr)

            if clone_child_stack != 0:
                ql.archfunc.set_sp(clone_child_stack)
            regreturn = 0
            ql.nprint("clone(new_stack = %x, flags = %x, tls = %x, ptidptr = %x, ctidptr = %x) = %d" % (clone_child_stack, clone_flags, clone_newtls, clone_parent_tidptr, clone_child_tidptr, regreturn))
            ql_definesyscall_return(ql, regreturn)
        ql.uc.emu_stop()
        return

    if clone_flags & CLONE_PARENT_SETTID == CLONE_PARENT_SETTID:
        set_child_tid_addr = clone_parent_tidptr

    th = Thread(ql, ql.thread_management, total_time = f_th.remaining_time(), set_child_tid_addr = set_child_tid_addr)
    th.set_current_path(f_th.get_current_path())

    # Whether to set a new tls
    if clone_flags & CLONE_SETTLS == CLONE_SETTLS:
        th.set_special_settings_fuc(f_th.special_settings_fuc)
        if ql.arch == QL_X86:
            newtls = ql.uc.mem_read(clone_newtls, 4 * 3)
        else:
            newtls = clone_newtls
        th.set_special_settings_arg(newtls)

    if clone_flags & CLONE_CHILD_CLEARTID == CLONE_CHILD_CLEARTID:
        th.set_clear_child_tid_addr(clone_child_tidptr)

    # Set the stack and return value of the new thread
    # (the return value of the child thread is 0, and the return value of the parent thread is the tid of the child thread)
    # and save the current context.
    f_sp = ql.archfunc.get_sp()

    regreturn = 0
    ql_definesyscall_return(ql, regreturn)
    ql.archfunc.set_sp(clone_child_stack)
    th.save()

    ql.thread_management.cur_thread = th
    ql.dprint("[+] Currently running pid is: %d; tid is: %d " % (os.getpid() ,ql.thread_management.cur_thread.get_thread_id()))
    ql.nprint("clone(new_stack = %x, flags = %x, tls = %x, ptidptr = %x, ctidptr = %x) = %d" % (clone_child_stack, clone_flags, clone_newtls, clone_parent_tidptr, clone_child_tidptr, regreturn))

    # Restore the stack and return value of the parent process
    ql.archfunc.set_sp(f_sp)
    regreturn = th.get_thread_id()
    ql_definesyscall_return(ql, regreturn)

    # Break the parent process and enter the add new thread event
    ql.uc.emu_stop()
    f_th.stop_event = THREAD_EVENT_CREATE_THREAD
    f_th.stop_return_val = th

    ql.thread_management.cur_thread = f_th
    ql.dprint("[+] Currently running pid is: %d; tid is: %d " % (os.getpid() ,ql.thread_management.cur_thread.get_thread_id()))
    ql.nprint("clone(new_stack = %x, flags = %x, tls = %x, ptidptr = %x, ctidptr = %x) = %d" % (clone_child_stack, clone_flags, clone_newtls, clone_parent_tidptr, clone_child_tidptr, regreturn))


def ql_syscall_set_tid_address(ql, set_tid_address_tidptr, null0, null1, null2, null3, null4):
    if ql.thread_management == None:
        regreturn = os.getpid()
    else:
        ql.thread_management.cur_thread.set_clear_child_tid_addr(set_tid_address_tidptr)
        regreturn = ql.thread_management.cur_thread.get_thread_id()
    ql.nprint("set_tid_address(%x) = %d" % (set_tid_address_tidptr, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_set_robust_list(ql, set_robust_list_head_ptr, set_robust_list_head_len, null0, null1, null2, null3):
    if ql.thread_management == None:
        regreturn = 0
    else:
        ql.thread_management.cur_thread.robust_list_head_ptr = set_robust_list_head_ptr
        ql.thread_management.cur_thread.robust_list_head_len = set_robust_list_head_len
    regreturn = 0
    ql.nprint("set_robust_list(%x, %x) = %d"%(set_robust_list_head_ptr, set_robust_list_head_len, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_futex(ql, futex_uaddr, futex_op, futex_val, futex_timeout, futex_uaddr2, futex_val3):
    FUTEX_WAIT = 0
    FUTEX_WAKE = 1
    FUTEX_FD = 2
    FUTEX_REQUEUE = 3
    FUTEX_CMP_REQUEUE = 4
    FUTEX_WAKE_OP = 5
    FUTEX_LOCK_PI = 6
    FUTEX_UNLOCK_PI = 7
    FUTEX_TRYLOCK_PI = 8
    FUTEX_WAIT_BITSET = 9
    FUTEX_WAKE_BITSET = 10
    FUTEX_WAIT_REQUEUE_PI = 11
    FUTEX_CMP_REQUEUE_PI = 12
    FUTEX_PRIVATE_FLAG = 128

    if futex_op & (FUTEX_PRIVATE_FLAG - 1) == FUTEX_WAIT:
        def futex_wait_addr(ql, th, arg):
            addr, val = arg
            if ql.unpack32(ql.uc.mem_read(addr, 4)) != val:
                return False
            else:
                return True
        ql.uc.emu_stop()
        ql.thread_management.cur_thread.blocking()
        ql.thread_management.cur_thread.set_blocking_condition(futex_wait_addr, [futex_uaddr, futex_val])
        regreturn = 0
        ql.nprint("futex(%x, %d, %d, %x) = %d" % (futex_uaddr, futex_op, futex_val, futex_timeout, regreturn))
    elif futex_op & (FUTEX_PRIVATE_FLAG - 1) == FUTEX_WAKE:
        regreturn = 0
        ql.nprint("futex(%x, %d, %d) = %d" % (futex_uaddr, futex_op, futex_val, regreturn))
    else:
        ql.nprint("futex(%x, %d, %d) = ?" % (futex_uaddr, futex_op, futex_val))
        ql.uc.emu_stop()
        ql.thread_management.cur_thread.stop()
        ql.thread_management.cur_thread.stop_event = THREAD_EVENT_EXIT_GROUP_EVENT
        regreturn = 0

    ql_definesyscall_return(ql, regreturn)


def ql_syscall_gettid(ql, null0, null1, null2, null3, null4, null5):
    th = ql.thread_management.cur_thread
    regreturn = th.get_thread_id()    
    ql.nprint("gettid() = %d" % regreturn)
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_pipe(ql, pipe_pipefd, null0, null1, null2, null3, null4):
    rd, wd = ql_pipe.open()

    idx1 = -1
    for i in range(256):
        if ql.file_des[i] == 0:
            idx1 = i
            break
    if idx1 == -1:
        regreturn = -1
    else:
        idx2 = -1
        for i in range(256):
            if ql.file_des[i] == 0 and i != idx1:
                idx2 = i
                break
        if idx2 == -1:
            regreturn = -1
        else:
            ql.file_des[idx1] = rd
            ql.file_des[idx2] = wd
            if ql.arch == QL_MIPS32EL:
                ql.uc.reg_write(UC_MIPS_REG_V1, idx2)
                regreturn = idx1
            else:
                ql.uc.mem_write(pipe_pipefd, ql.pack32(idx1) + ql.pack32(idx2))
                regreturn = 0

    ql.nprint("pipe(%x, [%d, %d]) = %d" % (pipe_pipefd, idx1, idx2, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_nice(ql, nice_inc, null0, null1, null2, null3, null4):
    regreturn = 0
    ql.nprint("nice(%d) = %d" % (nice_inc, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_getpriority(ql, getpriority_which, getpriority_who, null1, null2, null3, null4):
    base = os.getpriority(getpriority_which, getpriority_who)
    regreturn = base
    ql.nprint("getpriority(0x%x, 0x%x) = %d" % (getpriority_which, getpriority_who, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_sendfile64(ql, sendfile64_out_fd, sendfile64_in_fd, sendfile64_offest, sendfile64_count, null0, null1):
    if sendfile64_out_fd >= 0 and sendfile64_out_fd < 256 and sendfile64_in_fd >= 0 and sendfile64_in_fd < 256:
        ql.file_des[sendfile64_in_fd].lseek(ql.unpack32(ql.uc.mem_read(sendfile64_offest, 4)))
        buf = ql.file_des[sendfile64_in_fd].read(sendfile64_count)
        regreturn = ql.file_des[sendfile64_out_fd].write(buf)
    else:
        regreturn = -1

    ql.nprint("sendfile64(%d, %d, %x, %d) = %d" % (sendfile64_out_fd, sendfile64_in_fd, sendfile64_offest, sendfile64_count, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_truncate(ql, path, length, null0, null1, null2, null3):
    path = ql_read_string(ql, path)
    real_path = ql_transform_to_real_path(ql, path)
    st_size = os.stat(real_path).st_size

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

    ql.nprint('truncate(%s, 0x%x) = %d' % (path, length, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_ftruncate(ql, ftrunc_fd, ftrunc_length, null0, null1, null2, null3):
    real_path = ql.file_des[ftrunc_fd].name
    path = real_path.split('/')[-1]
    st_size = os.stat(real_path).st_size

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

    ql.nprint('ftruncate(%d, 0x%x) = %d' % (ftrunc_fd, ftrunc_length, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_unlink(ql, unlink_pathname, null0, null1, null2, null3, null4):
    pathname = ql_read_string(ql, unlink_pathname)
    real_path = ql_transform_to_real_path(ql, pathname)
    opened_fds = [getattr(ql.file_des[i], 'name', None) for i in range(256) if ql.file_des[i] != 0]
    path = pathlib.Path(real_path)

    if any((real_path not in opened_fds, path.is_block_device(), path.is_fifo(), path.is_socket(), path.is_symlink())):
        try:
            os.unlink(real_path)
            regreturn = 0
        except FileNotFoundError:
            ql.dprint('[!] No such file or directory')
            regreturn = -1
        except:
            regreturn = -1
    else:
        regreturn = -1

    ql.nprint('unlink(%s) = %d' % (pathname, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_unlinkat(ql, dirfd, pathname, flag, null0, null1, null2):
    # fix me. dirfd(relative path) not implement.
    file_path = ql_read_string(ql, pathname)
    real_path = ql_transform_to_real_path(ql, file_path)
    ql.nprint("unlinkat(%d, %s, 0%o)" % (dirfd, real_path, flag))
    try:
        os.unlink(real_path)
        regreturn = 0
    except FileNotFoundError:
        ql.dprint("[!] No such file or directory")
        regreturn = -1
    except:
        regreturn = -1
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_mknodat(ql, dirfd, pathname, mode, dev, null0, null1):
    # fix me. dirfd(relative path) not implement.
    file_path = ql_read_string(ql, pathname)
    real_path = ql_transform_to_real_path(ql, file_path)
    ql.nprint("mknodat(%d, %s, 0%o, %d)" % (dirfd, real_path, mode, dev))
    try:
        os.mknod(real_path, mode, dev)
        regreturn = 0
    except:
        regreturn = -1
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_umask(ql, mode, null0, null1, null2, null3, null4):
    oldmask = os.umask(mode)
    ql.nprint("umask(0%o) return oldmask 0%o" % (mode, oldmask))
    regreturn = oldmask
    ql_definesyscall_return(ql, regreturn)
