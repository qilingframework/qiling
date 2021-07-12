#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


from unicorn import (
    UC_PROT_ALL,
    UC_PROT_EXEC,
    UC_PROT_NONE,
    UC_PROT_READ,
    UC_PROT_WRITE,
)

from qiling.const import *
from qiling.os.linux.thread import *
from qiling.os.posix.filestruct import *
from qiling.os.filestruct import *
from qiling.os.posix.const import *
from qiling.os.posix.const_mapping import *
from qiling.exception import *


def ql_syscall_munmap(ql, munmap_addr, munmap_len, *args, **kw):

    # get all mapped fd with flag MAP_SHARED and we definitely dont want to wipe out share library
    mapped_fd = [fd for fd in ql.os.fd if fd != 0 and isinstance(fd, ql_file) and fd._is_map_shared and not (fd.name.endswith(".so") or fd.name.endswith(".dylib"))]

    if len(mapped_fd):
        all_mem_info = [_mem_info for _, _, _, _mem_info in ql.mem.map_info if _mem_info not in ("[mapped]", "[stack]", "[hook_mem]")]

        for _fd in mapped_fd:
            if _fd.name in [each.split()[-1] for each in all_mem_info]:
                ql.log.debug("Flushing file: %s" % _fd.name)
                # flushes changes to disk file
                _buff = ql.mem.read(munmap_addr, munmap_len)
                _fd.lseek(_fd._mapped_offset)
                _fd.write(_buff)

    munmap_len = ((munmap_len + 0x1000 - 1) // 0x1000) * 0x1000
    ql.mem.unmap(munmap_addr, munmap_len)
    regreturn = 0
    return regreturn


def ql_syscall_madvise(ql, madvise_addr, madvise_length, madvise_advice, *args, **kw):
    MADV_DONTNEED = 4

    if madvise_advice == MADV_DONTNEED:
        ql.mem.write(madvise_addr, b'\x00' * madvise_length)

    regreturn = 0
    return regreturn


def ql_syscall_mprotect(ql, start, mlen, prot, *args, **kw):
    regreturn = 0
    ql.log.debug("mprotect(0x%x, 0x%x, %s) = %d" % (start, mlen, mmap_prot_mapping(prot), regreturn))

    try:
        ql.mem.protect(start, mlen, prot)
    except Exception as e:
        ql.log.debug(e)
        raise QlMemoryMappedError("Error: change protection at: %x - %x" % (start, start + mlen - 1))

    return regreturn


def syscall_mmap_impl(ql, addr, mlen, prot, flags, fd, pgoffset, ver):
    MAP_ANONYMOUS = 32
    MAP_SHARED = 1
    MAP_FIXED = 0x10
    api_name = None

    if ver == 1:
        api_name = "mmap"
    elif ver == 2:
        api_name = "mmap2"
    elif ver == 0:
        api_name = "old_mmap"
    else:
        raise QlMemoryMappedError("Error: unknown mmap syscall!")

    ql.log.debug("%s(0x%x, 0x%x, %s (0x%x), %s (0x%x), %x, 0x%x)" % (
                 api_name, addr, mlen, mmap_prot_mapping(prot), prot, mmap_flag_mapping(flags), flags, fd, pgoffset))

    # FIXME
    # this is ugly patch, we might need to get value from elf parse,
    # is32bit or is64bit value not by arch
    if (ql.archtype == QL_ARCH.ARM64) or (ql.archtype == QL_ARCH.X8664):
        fd = ql.unpack64(ql.pack64(fd))
    elif (ql.archtype == QL_ARCH.MIPS):
        fd = ql.unpack32s(ql.mem.read(fd, 4))
        pgoffset = ql.unpack32(ql.mem.read(pgoffset, 4))
        MAP_ANONYMOUS = 2048
        if ver == 2:
            pgoffset = pgoffset * 4096
    elif (ql.archtype== QL_ARCH.ARM) and (ql.ostype== QL_OS.QNX):
        MAP_ANONYMOUS=0x00080000
        mmap_id = ql.unpack32s(ql.pack32s(fd))
    else:
        fd = ql.unpack32s(ql.pack32(fd))
        if ver == 2:
            pgoffset = pgoffset * 4096

    mmap_base = addr
    need_mmap = True
    eff_mmap_size = ((mlen + 0x1000 - 1) // 0x1000) * 0x1000

    # initial ql.loader.mmap_address
    if addr != 0 and ql.mem.is_mapped(addr, mlen):
        if (flags & MAP_FIXED) > 0:
            ql.log.debug("%s - MAP_FIXED, mapping not needed" % api_name)
            try:
                ql.mem.protect(addr, mlen, prot)
            except Exception as e:
                ql.log.debug(e)
                raise QlMemoryMappedError("Error: change protection at: 0x%x - 0x%x" % (addr, addr + eff_mmap_size - 1))
            need_mmap = False

    # initialized mapping
    if need_mmap:
        if (flags & MAP_FIXED) > 0:
            mmap_base = addr
        else:
            mmap_base = ql.loader.mmap_address
        ql.loader.mmap_address = mmap_base + eff_mmap_size
        ql.log.debug("%s - mapping needed for 0x%x" % (api_name, addr))
        try:
            ql.mem.map(mmap_base, eff_mmap_size, info=("[syscall_%s]" % api_name))
        except Exception as e:
            raise QlMemoryMappedError("Error: mapping needed but failed")

    ql.log.debug("%s - addr range  0x%x - 0x%x: " % (api_name, mmap_base, mmap_base + eff_mmap_size - 1))

    # FIXME: MIPS32 Big Endian
    try:
        ql.mem.write(mmap_base, b'\x00' * eff_mmap_size)
    except Exception as e:
        raise QlMemoryMappedError("Error: trying to zero memory")

    if ((flags & MAP_ANONYMOUS) == 0) and 0 <= fd < NR_OPEN and ql.os.fd[fd] != 0:
        ql.os.fd[fd].lseek(pgoffset)
        data = ql.os.fd[fd].read(mlen)
        mem_info = str(ql.os.fd[fd].name)
        ql.os.fd[fd]._is_map_shared = flags & MAP_SHARED
        ql.os.fd[fd]._mapped_offset = pgoffset
        ql.log.debug("mem write : " + hex(len(data)))
        ql.log.debug("mem mmap  : " + mem_info)
        ql.mem.add_mapinfo(mmap_base,
                           mmap_base + eff_mmap_size,
                           mem_p=UC_PROT_ALL,
                           mem_info=("[%s] " % api_name) + mem_info)
        try:
            ql.mem.write(mmap_base, data)
        except Exception as e:
            ql.log.debug(e)
            raise QlMemoryMappedError("Error: trying to write memory: ")

    ql.log.debug("%s(0x%x, 0x%x, 0x%x, 0x%x, %x, 0x%x) = 0x%x" %
                 (api_name, addr, mlen, prot, flags, fd, pgoffset, mmap_base))
    return mmap_base


def ql_syscall_old_mmap(ql, struct_mmap_args, *args, **kw):
    # according to the linux kernel this is only for the ia32 compatibility
    _struct = []

    for offset in range(0, 0x18, 4):
        data = ql.mem.read(struct_mmap_args + offset, 4)
        _struct.append(int.from_bytes(data, 'little'))

    mmap_addr, mmap_length, mmap_prot, mmap_flags, mmap_fd, mmap_offset = _struct

    return syscall_mmap_impl(ql, mmap_addr, mmap_length, mmap_prot, mmap_flags, mmap_fd, mmap_offset, 0)


def ql_syscall_mmap(ql, mmap_addr, mmap_length, mmap_prot, mmap_flags, mmap_fd, mmap_pgoffset):
    return syscall_mmap_impl(ql, mmap_addr, mmap_length, mmap_prot, mmap_flags, mmap_fd, mmap_pgoffset, 1)


def ql_syscall_mmap2(ql, mmap2_addr, mmap2_length, mmap2_prot, mmap2_flags, mmap2_fd, mmap2_pgoffset):
    return syscall_mmap_impl(ql, mmap2_addr, mmap2_length, mmap2_prot, mmap2_flags, mmap2_fd, mmap2_pgoffset, 2)
