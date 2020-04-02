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
import itertools

# Remove import fcntl due to Windows Limitation
#import fcntl

from unicorn import *
from unicorn.arm_const import *
from unicorn.x86_const import *
from unicorn.arm64_const import *
from unicorn.mips_const import *

# impport read_string and other commom utils.
from qiling.os.utils import *
from qiling.const import *
from qiling.os.linux.thread import *
from qiling.const import *
from qiling.os.posix.filestruct import *
from qiling.os.posix.constant_mapping import *
from qiling.utils import *

def ql_syscall_munmap(ql, munmap_addr , munmap_len, null0, null1, null2, null3):
    munmap_len = ((munmap_len + 0x1000 - 1) // 0x1000) * 0x1000
    ql.uc.mem_unmap(munmap_addr, munmap_len)
    regreturn = 0

    map_info = ql.map_info
    unmap_range = []
    munmap_end = munmap_addr+munmap_len

    for idx, val in enumerate(map_info):
        mem_start, mem_end, prot, info = val
        if mem_start <= munmap_addr <= mem_end or mem_start <= munmap_end <= mem_end:
            unmap_range.append(val)
            map_info[idx] = []

    for start, end, prot, info in unmap_range:
        if start < munmap_addr < end:
            new_start = start
            new_prot = prot
            new_info = info
            break
    else:
        new_start = 0

    for start, end, _, _ in unmap_range:
        if start < munmap_end <= end:
            new_end = munmap_addr
            break
    else:
        new_end = 0

    ql.map_info = [each for each in map_info if each != []]

    if new_start and new_end: # need to insert extra mapping area
        ql.insert_map_info(new_start, new_end, new_prot, new_info)

    ql.nprint("munmap(0x%x, 0x%x) = %d" % (munmap_addr , munmap_len, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_madvise(ql, null0, null1, null2, null3, null4, null5):
    regreturn = 0
    ql.nprint("madvise() = %d" %  regreturn)
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_mprotect(ql, mprotect_start, mprotect_len, mprotect_prot, null0, null1, null2):
    regreturn = 0
    ql.nprint("mprotect(0x%x, 0x%x, 0x%x) = %d" % (mprotect_start, mprotect_len, mprotect_prot, regreturn))
    ql.dprint(1, "[+] mprotect(0x%x, 0x%x, %s) = %d" % (
    mprotect_start, mprotect_len, mmap_prot_mapping(mprotect_prot), regreturn))

    new_prot = []
    prot_dict = {"PROT_READ": "r", "PROT_WRITE": "w", "PROT_EXEC": "x"}
    mapped_prot = mmap_prot_mapping(mprotect_prot)

    for idx, val in prot_dict.items():
        if "PROT_NONE" in mapped_prot:
            new_prot = "---"
            break
        elif idx in mapped_prot:
            new_prot.append(val)
        else:
            new_prot.append("-")

    new_prot = ''.join(new_prot)

    map_info = ql.map_info

    for idx, val in enumerate(map_info):
        start, end, prot, info = val
        if start < mprotect_start+mprotect_len-1 < end:
            map_info[idx] = [start, end, new_prot, info]

    ql.map_info = map_info

    ql_definesyscall_return(ql, regreturn)


def ql_syscall_old_mmap(ql, struct_mmap_args, null0, null1, null2, null3, null4):
    # according to the linux kernel this is only for the ia32 compatibility
    _struct = []

    for offset in range(0, 0x18, 4):
        data = ql.mem_read(struct_mmap_args + offset, 4)
        _struct.append(int.from_bytes(data, 'little'))

    mmap_addr, mmap_length, mmap_prot, mmap_flags, mmap_fd, mmap_offset = _struct
    ql.dprint(0, "[+] log old_mmap - old_mmap(0x%x, 0x%x, 0x%x, 0x%x, %d, %d)" % (
    mmap_addr, mmap_length, mmap_prot, mmap_flags, mmap_fd, mmap_offset))
    ql.dprint(1, "[+] log old_mmap - old_mmap(0x%x, 0x%x, %s, %s, %d, %d)" % (
    mmap_addr, mmap_length, mmap_prot_mapping(mmap_prot), mmap_flag_mapping(mmap_flags), mmap_fd, mmap_offset))

    # FIXME
    # this is ugly patch, we might need to get value from elf parse,
    # is32bit or is64bit value not by arch
    MAP_ANONYMOUS = 32

    if (ql.arch == QL_ARM64) or (ql.arch == QL_X8664):
        mmap_fd = ql.unpack64(ql.pack64(mmap_fd))

    elif (ql.arch == QL_MIPS32):
        mmap_fd = ql.unpack32s(ql.uc.mem_read(mmap_fd, 4))
        mmap_offset = ql.unpack32(ql.uc.mem_read(mmap_offset, 4))
        MAP_ANONYMOUS=2048

    else:
        mmap_fd = ql.unpack32s(ql.pack32(mmap_fd))

    mmap_base = mmap_addr
    need_mmap = True

    if mmap_addr != 0 and (mmap_addr < ql.mmap_start):
        need_mmap = False

    # initial ql.mmap_start
    if mmap_addr == 0:
        mmap_base = ql.mmap_start
        ql.mmap_start = mmap_base + ((mmap_length + 0x1000 - 1) // 0x1000) * 0x1000

    ql.dprint(0, "[+] log old_mmap - return addr : " + hex(mmap_base))
    ql.dprint(0, "[+] log old_mmap - addr range  : " + hex(mmap_base) + ' - ' + hex(
        mmap_base + ((mmap_length + 0x1000 - 1) // 0x1000) * 0x1000))

    # initialized mapping
    if need_mmap:
        ql.dprint(0, "[+] log old_mmap - mapping needed")
        try:
            ql.uc.mem_map(mmap_base, ((mmap_length + 0x1000 - 1) // 0x1000) * 0x1000)
        except:
            ql.show_map_info()
            raise

    ql.uc.mem_write(mmap_base, b'\x00' * (((mmap_length + 0x1000 - 1) // 0x1000) * 0x1000))

    mem_s = mmap_base
    mem_e = mmap_base + ((mmap_length + 0x1000 - 1) // 0x1000) * 0x1000
    mem_info = '[mapped]'
    mem_p = []
    prot_dict = {"PROT_READ": "r", "PROT_WRITE": "w", "PROT_EXEC": "x"}

    for idx, val in prot_dict.items():
        if idx in mmap_prot_mapping(mmap_prot):
            mem_p.append(val)
        else:
            mem_p.append("-")

    mem_p = ''.join(mem_p)

    if ((mmap_flags & MAP_ANONYMOUS) == 0) and mmap_fd < 256 and ql.file_des[mmap_fd] != 0:
        ql.file_des[mmap_fd].lseek(mmap_offset)
        data = ql.file_des[mmap_fd].read(mmap_length)

        ql.dprint(0, "[+] log mem wirte : " + hex(len(data)))
        ql.dprint(0, "[+] log mem mmap  : " + str(ql.file_des[mmap_fd].name))

        ql.uc.mem_write(mmap_base, data)
        mem_info = ql.file_des[mmap_fd].name

    ql.insert_map_info(mem_s, mem_e, mem_p, mem_info)


    ql.nprint("old_mmap(0x%x, 0x%x, 0x%x, 0x%x, %d, %d) = 0x%x" % (mmap_addr, mmap_length, mmap_prot, mmap_flags, mmap_fd, mmap_offset, mmap_base))
    regreturn = mmap_base
    ql.dprint(0, "[+] mmap_base is 0x%x" % regreturn)

    ql_definesyscall_return(ql, regreturn)


def ql_syscall_mmap(ql, mmap2_addr, mmap2_length, mmap2_prot, mmap2_flags, mmap2_fd, mmap2_pgoffset):
    ql.dprint(0, "[+] log mmap - mmap(0x%x, 0x%x, 0x%x, 0x%x, %d, %d)" % (
    mmap2_addr, mmap2_length, mmap2_prot, mmap2_flags, mmap2_fd, mmap2_pgoffset))
    ql.dprint(1, "[+] log mmap - mmap(0x%x, 0x%x, %s, %s, %d, %d)" % (
    mmap2_addr, mmap2_length, mmap_prot_mapping(mmap2_prot), mmap_flag_mapping(mmap2_flags), mmap2_fd, mmap2_pgoffset))

    # FIXME
    # this is ugly patch, we might need to get value from elf parse,
    # is32bit or is64bit value not by arch
    MAP_ANONYMOUS = 32

    if (ql.arch == QL_ARM64) or (ql.arch == QL_X8664):
        mmap2_fd = ql.unpack64(ql.pack64(mmap2_fd))

    elif (ql.arch == QL_MIPS32):
        mmap2_fd = ql.unpack32s(ql.uc.mem_read(mmap2_fd, 4))
        mmap2_pgoffset = ql.unpack32(ql.uc.mem_read(mmap2_pgoffset, 4))
        MAP_ANONYMOUS=2048

    else:
        mmap2_fd = ql.unpack32s(ql.pack32(mmap2_fd))

    mmap_base = mmap2_addr
    need_mmap = True

    if mmap2_addr != 0 and (mmap2_addr < ql.mmap_start):
        need_mmap = False

        # initial ql.mmap_start
    if mmap2_addr == 0:
        mmap_base = ql.mmap_start
        ql.mmap_start = mmap_base + ((mmap2_length + 0x1000 - 1) // 0x1000) * 0x1000

    ql.dprint(0, "[+] log mmap - return addr : " + hex(mmap_base))
    ql.dprint(0, "[+] log mmap - addr range  : " + hex(mmap_base) + ' - ' + hex(
        mmap_base + ((mmap2_length + 0x1000 - 1) // 0x1000) * 0x1000))

    # initialized mapping
    if need_mmap:
        ql.dprint(0, "[+] log mmap - mapping needed")
        try:
            ql.uc.mem_map(mmap_base, ((mmap2_length + 0x1000 - 1) // 0x1000) * 0x1000)
        except:
            ql.show_map_info()
            raise

    # FIXME: Big Endian Patch
    try:
        ql.uc.mem_write(mmap_base, b'\x00' * (((mmap2_length + 0x1000 - 1) // 0x1000) * 0x1000))
    except:
        pass


    mem_s = mmap_base
    mem_e = mmap_base + ((mmap2_length + 0x1000 - 1) // 0x1000) * 0x1000
    mem_info = '[mapped]'
    mem_p = []
    prot_dict = {"PROT_READ": "r", "PROT_WRITE": "w", "PROT_EXEC": "x"}

    for idx, val in prot_dict.items():
        if idx in mmap_prot_mapping(mmap2_prot):
            mem_p.append(val)
        else:
            mem_p.append("-")

    mem_p = ''.join(mem_p)

    if ((mmap2_flags & MAP_ANONYMOUS) == 0) and mmap2_fd < 256 and ql.file_des[mmap2_fd] != 0:
        ql.file_des[mmap2_fd].lseek(mmap2_pgoffset)
        data = ql.file_des[mmap2_fd].read(mmap2_length)

        ql.dprint(0, "[+] log mem wirte : " + hex(len(data)))
        ql.dprint(0, "[+] log mem mmap  : " + str(ql.file_des[mmap2_fd].name))

        ql.uc.mem_write(mmap_base, data)
        mem_info = ql.file_des[mmap2_fd].name

    ql.insert_map_info(mem_s, mem_e, mem_p, mem_info)


    ql.nprint("mmap(0x%x, 0x%x, 0x%x, 0x%x, %d, %d) = 0x%x" % (mmap2_addr, mmap2_length, mmap2_prot, mmap2_flags,
                                                               mmap2_fd, mmap2_pgoffset, mmap_base))
    regreturn = mmap_base
    ql.dprint(0, "[+] mmap_base is 0x%x" % regreturn)

    ql_definesyscall_return(ql, regreturn)


def ql_syscall_mmap2(ql, mmap2_addr, mmap2_length, mmap2_prot, mmap2_flags, mmap2_fd, mmap2_pgoffset):
    # this is ugly patch, we might need to get value from elf parse,
    # is32bit or is64bit value not by arch

    MAP_ANONYMOUS=32

    if (ql.arch == QL_ARM64) or (ql.arch == QL_X8664):
        mmap2_fd = ql.unpack64(ql.pack64(mmap2_fd))

    elif (ql.arch == QL_MIPS32):
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

    ql.dprint(0, "[+] log mmap2 - mmap2(0x%x, 0x%x, 0x%x, 0x%x, %d, %d)" % (
    mmap2_addr, mmap2_length, mmap2_prot, mmap2_flags, mmap2_fd, mmap2_pgoffset))
    ql.dprint(1, "[+] log mmap2 - mmap2(0x%x, 0x%x, %s, %s, %d, %d)" % (
    mmap2_addr, mmap2_length, mmap_prot_mapping(mmap2_prot), mmap_flag_mapping(mmap2_flags), mmap2_fd, mmap2_pgoffset))
    ql.dprint(0, "[+] log mmap2 - return addr : " + hex(mmap_base))
    ql.dprint(0, "[+] log mmap2 - addr range  : " + hex(mmap_base) + ' - ' + hex(
        mmap_base + ((mmap2_length + 0x1000 - 1) // 0x1000) * 0x1000))

    if need_mmap:
        ql.dprint(0, "[+] log mmap - mapping needed")
        try:
            ql.uc.mem_map(mmap_base, ((mmap2_length + 0x1000 - 1) // 0x1000) * 0x1000)
        except:
            ql.show_map_info()
            raise

    ql.uc.mem_write(mmap_base, b'\x00' * (((mmap2_length + 0x1000 - 1) // 0x1000) * 0x1000))

    mem_s = mmap_base
    mem_e = mmap_base + ((mmap2_length + 0x1000 - 1) // 0x1000) * 0x1000
    mem_info = '[mapped]'
    mem_p = []
    prot_dict = {"PROT_READ": "r", "PROT_WRITE": "w", "PROT_EXEC": "x"}

    for idx, val in prot_dict.items():
        if idx in mmap_prot_mapping(mmap2_prot):
            mem_p.append(val)
        else:
            mem_p.append("-")

    mem_p = ''.join(mem_p)

    if ((mmap2_flags & MAP_ANONYMOUS) == 0) and mmap2_fd < 256 and ql.file_des[mmap2_fd] != 0:
        ql.file_des[mmap2_fd].lseek(mmap2_pgoffset)
        data = ql.file_des[mmap2_fd].read(mmap2_length)

        ql.dprint(0, "[+] log2 mem wirte : " + hex(len(data)))
        ql.dprint(0, "[+] log2 mem mmap  : " + str(ql.file_des[mmap2_fd].name))
        ql.uc.mem_write(mmap_base, data)

        mem_info = ql.file_des[mmap2_fd].name

    ql.insert_map_info(mem_s, mem_e, mem_p, mem_info)

    ql.nprint("mmap2(0x%x, 0x%x, 0x%x, 0x%x, %d, %d) = 0x%x" % (mmap2_addr, mmap2_length, mmap2_prot, mmap2_flags, mmap2_fd, mmap2_pgoffset, mmap_base))

    regreturn = mmap_base
    ql.dprint(0, "[+] mmap2_base is 0x%x" % regreturn)

    ql_definesyscall_return(ql, regreturn)
