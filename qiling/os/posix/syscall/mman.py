#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn import UC_PROT_ALL

from qiling import Qiling
from qiling.exception import QlMemoryMappedError
from qiling.os.filestruct import ql_file
from qiling.os.posix.const_mapping import *

def ql_syscall_munmap(ql: Qiling, addr: int, length: int):

    # get all mapped fd with flag MAP_SHARED and we definitely dont want to wipe out share library
    mapped_fd = [fd for fd in ql.os.fd if fd != 0 and isinstance(fd, ql_file) and fd._is_map_shared and not (fd.name.endswith(".so") or fd.name.endswith(".dylib"))]

    if mapped_fd:
        all_mem_info = [_mem_info for _, _, _, _mem_info in ql.mem.map_info if _mem_info not in ("[mapped]", "[stack]", "[hook_mem]")]

        for _fd in mapped_fd:
            if _fd.name in [each.split()[-1] for each in all_mem_info]:
                ql.log.debug("Flushing file: %s" % _fd.name)
                # flushes changes to disk file
                _buff = ql.mem.read(addr, length)
                _fd.lseek(_fd._mapped_offset)
                _fd.write(_buff)

    length = ((length + 0x1000 - 1) // 0x1000) * 0x1000
    ql.mem.unmap(addr, length)

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


def syscall_mmap_impl(ql: Qiling, addr: int, mlen: int, prot: int, flags: int, fd: int, pgoffset: int, ver: int):
    MAP_SHARED = 0x01
    MAP_FIXED = 0x10
    MAP_ANONYMOUS = 0x20

    api_name = {
        0 : 'old_mmap',
        1 : 'mmap',
        2 : 'mmap2'
    }[ver]

    # ql.log.debug(f'{api_name}({addr:#x}, {mlen:#x}, {mmap_prot_mapping(prot)} ({prot:#x}), {mmap_flag_mapping(flags)} ({flags:#x}), {fd:d}, {pgoffset:#x})')

    # FIXME
    # this is ugly patch, we might need to get value from elf parse,
    # is32bit or is64bit value not by arch
    if (ql.archtype == QL_ARCH.ARM64) or (ql.archtype == QL_ARCH.X8664):
        fd = ql.unpack64(ql.pack64(fd))
    elif (ql.archtype == QL_ARCH.MIPS):
        MAP_ANONYMOUS = 2048
        if ver == 2:
            pgoffset = pgoffset * 4096
    elif (ql.archtype== QL_ARCH.ARM) and (ql.ostype== QL_OS.QNX):
        MAP_ANONYMOUS=0x00080000
        fd = ql.unpack32s(ql.pack32s(fd))
    else:
        fd = ql.unpack32s(ql.pack32(fd))
        if ver == 2:
            pgoffset = pgoffset * 4096

    mmap_base = addr
    need_mmap = True
    eff_mmap_size = ((mlen + 0x1000 - 1) // 0x1000) * 0x1000
    # align eff_mmap_size to page boundary
    aligned_address = (addr >> 12) << 12
    eff_mmap_size -= mmap_base - aligned_address

    # initial ql.loader.mmap_address
    if addr != 0 and ql.mem.is_mapped(addr, mlen):
        if (flags & MAP_FIXED) > 0:
            ql.log.debug("%s - MAP_FIXED, mapping not needed" % api_name)
            try:
                ql.mem.protect(addr, mlen, prot)
            except Exception as e:
                ql.log.debug(e)
                raise QlMemoryMappedError("Error: change protection at: 0x%x - 0x%x" % (addr, addr + mlen - 1))
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

        # FIXME: shouldn't we use ql.mem.map instead?
        ql.mem.add_mapinfo(mmap_base,
                           mmap_base + eff_mmap_size,
                           mem_p=UC_PROT_ALL,
                           mem_info=("[%s] " % api_name) + mem_info)
        try:
            ql.mem.write(mmap_base, data)
        except Exception as e:
            ql.log.debug(e)
            raise QlMemoryMappedError("Error: trying to write memory: ")

    return mmap_base


def ql_syscall_old_mmap(ql: Qiling, struct_mmap_args: int):
    # according to the linux kernel this is only for the ia32 compatibility

    def __read_int(address: int) -> int:
        return ql.unpack32(ql.mem.read(address, 4))

    addr   = __read_int(struct_mmap_args + 0 * 4)
    length = __read_int(struct_mmap_args + 1 * 4)
    prot   = __read_int(struct_mmap_args + 2 * 4)
    flags  = __read_int(struct_mmap_args + 3 * 4)
    fd     = __read_int(struct_mmap_args + 4 * 4)
    offset = __read_int(struct_mmap_args + 5 * 4)

    return syscall_mmap_impl(ql, addr, length, prot, flags, fd, offset, 0)


def ql_syscall_mmap(ql: Qiling, addr: int, length: int, prot: int, flags: int, fd: int, pgoffset: int):
    return syscall_mmap_impl(ql, addr, length, prot, flags, fd, pgoffset, 1)


def ql_syscall_mmap2(ql: Qiling, addr: int, length: int, prot: int, flags: int, fd: int, pgoffset: int):
    return syscall_mmap_impl(ql, addr, length, prot, flags, fd, pgoffset, 2)

def ql_syscall_shmget(ql: Qiling, key: int, size: int, shmflg: int):
    if shmflg & IPC_CREAT:
        if shmflg & IPC_EXCL:
            if key in ql.os._shms:
                return EEXIST
        else:
            #addr = ql.mem.map_anywhere(size)
            ql.os._shms[key] = (key, size)
            return key
    else:
        if key not in ql.os._shms:
            return ENOENT

def ql_syscall_shmat(ql: Qiling, shmid: int, shmaddr: int, shmflg: int):
    # shmid == key
    # dummy implementation
    if shmid not in ql.os._shms:
        return EINVAL

    key, size = ql.os._shms[shmid]

    if shmaddr == 0:
        addr = ql.mem.map_anywhere(size)
    else:
        addr = ql.mem.map(shmaddr, size, info="[shm]")

    return addr