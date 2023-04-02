#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os
import re
from enum import IntFlag
from typing import Optional

from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS
from qiling.exception import QlMemoryMappedError
from qiling.os.filestruct import ql_file
from qiling.os.posix.const_mapping import *


def ql_syscall_munmap(ql: Qiling, addr: int, length: int):
    try:
        # find addr's enclosing memory range
        label = next(label for lbound, ubound, _, label, _ in ql.mem.get_mapinfo() if (lbound <= addr < ubound) and label.startswith(('[mmap]', '[mmap anonymous]')))
    except StopIteration:
        # nothing to do; cannot munmap what was not originally mmapped
        ql.log.debug(f'munmap: enclosing area for {addr:#x} was not mmapped')
    else:
        # extract the filename from the label by removing the boxed prefix
        fname = re.sub(r'^\[.+\]\s*', '', label)

        # if this is an anonymous mapping, there is no trailing file name
        if fname:
            try:
                # find the file that was originally mmapped into this region, to flush the changes.
                # if the fd was already closed, there is nothing left to do
                fd = next(fd for fd in ql.os.fd if isinstance(fd, ql_file) and os.path.basename(fd.name) == fname)
            except StopIteration:
                ql.log.debug(f'munmap: could not find matching fd, it might have been closed')
            else:
                # flushing memory contents to file is required only if mapping is shared / not private
                if fd._is_map_shared:
                    ql.log.debug(f'munmap: flushing "{fname}"')
                    content = ql.mem.read(addr, length)

                    fd.lseek(fd._mapped_offset)
                    fd.write(content)

        # unmap the enclosing memory region
        lbound = ql.mem.align(addr)
        ubound = ql.mem.align_up(addr + length)

        ql.mem.unmap(lbound, ubound - lbound)

    return 0


def ql_syscall_madvise(ql: Qiling, addr: int, length: int, advice: int):
    MADV_DONTNEED = 4

    if advice == MADV_DONTNEED:
        ql.mem.write(addr, b'\x00' * length)

    return 0


def ql_syscall_mprotect(ql: Qiling, start: int, mlen: int, prot: int):
    try:
        ql.mem.protect(start, mlen, prot)
    except Exception as e:
        ql.log.exception(e)

        raise QlMemoryMappedError(f'Error: change protection at: {start:#x} - {start + mlen - 1:#x}')

    return 0


def syscall_mmap_impl(ql: Qiling, addr: int, length: int, prot: int, flags: int, fd: int, pgoffset: int, ver: int):
    def __select_mmap_flags(archtype: QL_ARCH, ostype: QL_OS):
        """The mmap flags definitions differ between operating systems and architectures.
        This method provides the apropriate flags set based on those properties.
        """

        osflags = {
            QL_OS.LINUX:   mips_mmap_flags if archtype == QL_ARCH.MIPS else linux_mmap_flags,
            QL_OS.FREEBSD: freebsd_mmap_flags,
            QL_OS.MACOS:   macos_mmap_flags,
            QL_OS.QNX:     qnx_mmap_flags       # FIXME: only for arm?
        }[ostype]

        class mmap_flags(IntFlag):
            MAP_FILE      = osflags.MAP_FILE.value
            MAP_SHARED    = osflags.MAP_SHARED.value
            MAP_FIXED     = osflags.MAP_FIXED.value
            MAP_ANONYMOUS = osflags.MAP_ANONYMOUS.value

            # the following flags do not exist on all flags sets.
            # if not exists, set it to 0 so it would fail all bitwise-and checks
            MAP_FIXED_NOREPLACE = osflags.MAP_FIXED_NOREPLACE.value if hasattr(osflags, 'MAP_FIXED_NOREPLACE') else 0
            MAP_UNINITIALIZED = osflags.MAP_UNINITIALIZED.value if hasattr(osflags, 'MAP_UNINITIALIZED') else 0

        return mmap_flags

    api_name = ('old_mmap', 'mmap', 'mmap2')[ver]
    mmap_flags = __select_mmap_flags(ql.arch.type, ql.os.type)

    pagesize = ql.mem.pagesize
    mapping_size = ql.mem.align_up(length + (addr & (pagesize - 1)))

    ################################
    # determine mapping boundaries #
    ################################

    # as opposed to other systems, QNX allows specifying an unaligned base address
    # for fixed mappings. to keep it consistent across all systems we allocate the
    # enclosing pages of the requested area, while returning the requested fixed
    # base address.
    #
    # to help track this, we use the following variables:
    #   addr         : the address that becomes available, from program point of view
    #   lbound       : lower bound of actual mapping range (aligned to page)
    #   ubound       : upper bound of actual mapping range (aligned to page)
    #   mapping_size : actual mapping range size
    #
    # note that on non-QNX systems addr and lbound are equal.
    #
    # for example, assume requested base address and length are 0x774ec8d8 and 0x1800
    # respectively, then we allocate 3 pages as follows:
    #   [align(0x7700c8d8), align_up(0x7700c8d8 + 0x1800)] -> [0x7700c000, 0x7700f000]

    # if mapping is fixed, use the base address as-is
    if flags & (mmap_flags.MAP_FIXED | mmap_flags.MAP_FIXED_NOREPLACE):
        # on non-QNX systems, base must be aligned to page boundary
        if addr & (pagesize - 1) and ql.os.type != QL_OS.QNX:
            return -1   # errno: EINVAL

    # if not, use the base address as a hint but always above or equal to
    # the value specified in /proc/sys/vm/mmap_min_addr (here: mmap_address)
    else:
        addr = ql.mem.find_free_space(mapping_size, max(addr, ql.loader.mmap_address))

    # on non-QNX systems addr is already aligned to page boundary
    lbound = ql.mem.align(addr)
    ubound = lbound + mapping_size

    ##################################
    # make sure memory can be mapped #
    ##################################

    if flags & mmap_flags.MAP_FIXED_NOREPLACE:
        if not ql.mem.is_available(lbound, mapping_size):
            return -1   # errno: EEXIST

    elif flags & mmap_flags.MAP_FIXED:
        ql.log.debug(f'{api_name}: unmapping memory between {lbound:#x}-{ubound:#x} to make room for fixed mapping')
        ql.mem.unmap_between(lbound, ubound)

    #############################
    # determine mapping content #
    #############################

    if flags & mmap_flags.MAP_ANONYMOUS:
        data = b'' if flags & mmap_flags.MAP_UNINITIALIZED else b'\x00' * length
        label = '[mmap anonymous]'

    else:
        fd = ql.unpacks(ql.pack(fd))

        if fd not in range(NR_OPEN):
            return -1   # errno: EBADF

        f: Optional[ql_file] = ql.os.fd[fd]

        if f is None:
            return -1   # errno: EBADF

        # set mapping properties for future unmap
        f._is_map_shared = bool(flags & mmap_flags.MAP_SHARED)
        f._mapped_offset = pgoffset

        fname = f.name

        if isinstance(fname, bytes):
            fname = fname.decode()

        f.seek(pgoffset)

        data = f.read(length)
        label = f'[mmap] {os.path.basename(fname)}'

    try:
        # finally, we have everything we need to map the memory.
        #
        # we have to map it first as writeable so we can write data in it.
        # permissions are adjusted afterwards with protect.
        ql.mem.map(lbound, mapping_size, info=label)
    except QlMemoryMappedError:
        ql.log.debug(f'{api_name}: out of memory')
        return -1   # errono: ENOMEM
    else:
        if data:
            ql.mem.write(addr, data)

        ql.mem.protect(lbound, mapping_size, prot)

        return addr


def ql_syscall_old_mmap(ql: Qiling, struct_mmap_args: int):
    # according to the linux kernel this is only for the ia32 compatibility

    addr   = ql.mem.read_ptr(struct_mmap_args + 0 * 4, 4)
    length = ql.mem.read_ptr(struct_mmap_args + 1 * 4, 4)
    prot   = ql.mem.read_ptr(struct_mmap_args + 2 * 4, 4)
    flags  = ql.mem.read_ptr(struct_mmap_args + 3 * 4, 4)
    fd     = ql.mem.read_ptr(struct_mmap_args + 4 * 4, 4)
    offset = ql.mem.read_ptr(struct_mmap_args + 5 * 4, 4)

    return syscall_mmap_impl(ql, addr, length, prot, flags, fd, offset, 0)


def ql_syscall_mmap(ql: Qiling, addr: int, length: int, prot: int, flags: int, fd: int, pgoffset: int):
    return syscall_mmap_impl(ql, addr, length, prot, flags, fd, pgoffset, 1)


def ql_syscall_mmap2(ql: Qiling, addr: int, length: int, prot: int, flags: int, fd: int, pgoffset: int):
    if ql.os.type != QL_OS.QNX:
        pgoffset *= ql.mem.pagesize

    return syscall_mmap_impl(ql, addr, length, prot, flags, fd, pgoffset, 2)
