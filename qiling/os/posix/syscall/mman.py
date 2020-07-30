#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

from unicorn import (
    UC_PROT_ALL,
    UC_PROT_EXEC,
    UC_PROT_NONE,
    UC_PROT_READ,
    UC_PROT_WRITE,
)

from qiling.const import *
from qiling.os.linux.thread import *
from qiling.const import *
from qiling.os.posix.filestruct import *
from qiling.os.filestruct import *
from qiling.os.posix.const_mapping import *
from qiling.exception import *


def ql_syscall_munmap(ql, munmap_addr , munmap_len, *args, **kw):

    # get all mapped fd with flag MAP_SHARED and we definitely dont want to wipe out share library
    mapped_fd = [fd for fd in ql.os.fd if fd != 0 and isinstance(fd, ql_file) and fd._is_map_shared and not fd.name.endswith(".so")]
    if len(mapped_fd):
        all_mem_info = [_mem_info for _, _, _,  _mem_info in ql.mem.map_info if _mem_info not in ("[mapped]", "[stack]", "[hook_mem]")]

        for _fd in mapped_fd:
            if _fd.name in [each.split()[-1] for each in all_mem_info]:
                # flushes changes to disk file
                _buff = ql.mem.read(munmap_addr, munmap_len)
                _fd.lseek(_fd._mapped_offset)
                _fd.write(_buff)

    munmap_len = ((munmap_len + 0x1000 - 1) // 0x1000) * 0x1000
    ql.mem.unmap(munmap_addr, munmap_len)
    regreturn = 0

    ql.nprint("munmap(0x%x, 0x%x) = %d" % (munmap_addr , munmap_len, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_madvise(ql, *args, **kw):
    regreturn = 0
    ql.nprint("madvise() = %d" %  regreturn)
    ql.os.definesyscall_return(regreturn)


def ql_syscall_mprotect(ql, mprotect_start, mprotect_len, mprotect_prot, *args, **kw):
    regreturn = 0
    ql.nprint("mprotect(0x%x, 0x%x, 0x%x) = %d" % (mprotect_start, mprotect_len, mprotect_prot, regreturn))
    ql.dprint(D_INFO, "[+] mprotect(0x%x, 0x%x, %s) = %d" % (
    mprotect_start, mprotect_len, mmap_prot_mapping(mprotect_prot), regreturn))

    ql.os.definesyscall_return(regreturn)

def ql_syscall_old_mmap(ql, struct_mmap_args, *args, **kw):
    # according to the linux kernel this is only for the ia32 compatibility
    _struct = []

    for offset in range(0, 0x18, 4):
        data = ql.mem.read(struct_mmap_args + offset, 4)
        _struct.append(int.from_bytes(data, 'little'))

    mmap_addr, mmap_length, mmap_prot, mmap_flags, mmap_fd, mmap_offset = _struct
    ql.dprint(D_INFO, "[+] log old_mmap - old_mmap(0x%x, 0x%x, 0x%x, 0x%x, %d, %d)" % (
    mmap_addr, mmap_length, mmap_prot, mmap_flags, mmap_fd, mmap_offset))
    ql.dprint(D_INFO, "[+] log old_mmap - old_mmap(0x%x, 0x%x, %s, %s, %d, %d)" % (
    mmap_addr, mmap_length, mmap_prot_mapping(mmap_prot), mmap_flag_mapping(mmap_flags), mmap_fd, mmap_offset))

    # FIXME
    # this is ugly patch, we might need to get value from elf parse,
    # is32bit or is64bit value not by arch
    MAP_ANONYMOUS = 32

    if (ql.archtype== QL_ARCH.ARM64) or (ql.archtype== QL_ARCH.X8664):
        mmap_fd = ql.unpack64(ql.pack64(mmap_fd))

    elif (ql.archtype== QL_ARCH.MIPS):
        mmap_fd = ql.unpack32s(ql.mem.read(mmap_fd, 4))
        mmap_offset = ql.unpack32(ql.mem.read(mmap_offset, 4))
        MAP_ANONYMOUS=2048

    else:
        mmap_fd = ql.unpack32s(ql.pack32(mmap_fd))

    # initial ql.loader.mmap_address
    mmap_base = mmap_addr
    need_mmap = True

    if mmap_addr == 0:
        mmap_base = ql.loader.mmap_address
        ql.loader.mmap_address = mmap_base + ((mmap_length + 0x1000 - 1) // 0x1000) * 0x1000
    elif ql.mem.is_mapped(mmap_addr, mmap_length):
        need_mmap = False

    ql.dprint(D_INFO, "[+] log old_mmap - return addr : " + hex(mmap_base))
    ql.dprint(D_INFO, "[+] log old_mmap - addr range  : " + hex(mmap_base) + ' - ' + hex(
        mmap_base + ((mmap_length + 0x1000 - 1) // 0x1000) * 0x1000))

    # initialized mapping
    if need_mmap:
        ql.dprint(D_INFO, "[+] log old_mmap - mapping needed")
        try:
            ql.mem.map(mmap_base, ((mmap_length + 0x1000 - 1) // 0x1000) * 0x1000, info="[syscall_old_mmap]")
        except:
            ql.mem.show_mapinfo()
            raise

    ql.mem.write(mmap_base, b'\x00' * (((mmap_length + 0x1000 - 1) // 0x1000) * 0x1000))

    if ((mmap_flags & MAP_ANONYMOUS) == 0) and mmap_fd < 256 and ql.os.fd[mmap_fd] != 0:
        ql.os.fd[mmap_fd].lseek(mmap_offset)
        data = ql.os.fd[mmap_fd].read(mmap_length)
        mem_info = str(ql.os.fd[mmap_fd].name)
        ql.os.fd[mmap_fd]._is_map_shared = True
        ql.os.fd[mmap_fd]._mapped_offset = mmap_offset

        ql.dprint(D_INFO, "[+] log mem wirte : " + hex(len(data)))
        ql.dprint(D_INFO, "[+] log mem mmap  : " + mem_info)
        ql.mem.add_mapinfo(mmap_base,  mmap_base + (((mmap_length + 0x1000 - 1) // 0x1000) * 0x1000), mem_p = UC_PROT_ALL, mem_info = "[old_mmap] " + mem_info)
        ql.mem.write(mmap_base, data)
        

    ql.nprint("old_mmap(0x%x, 0x%x, 0x%x, 0x%x, %d, %d) = 0x%x" % (mmap_addr, mmap_length, mmap_prot, mmap_flags, mmap_fd, mmap_offset, mmap_base))
    regreturn = mmap_base
    ql.dprint(D_INFO, "[+] mmap_base is 0x%x" % regreturn)

    ql.os.definesyscall_return(regreturn)


def ql_syscall_mmap(ql, mmap_addr, mmap_length, mmap_prot, mmap_flags, mmap_fd, mmap_pgoffset):
    ql.dprint(D_INFO, "[+] log mmap - mmap(0x%x, 0x%x, 0x%x, 0x%x, %d, %d)" % (
    mmap_addr, mmap_length, mmap_prot, mmap_flags, mmap_fd, mmap_pgoffset))
    ql.dprint(D_INFO, "[+] log mmap - mmap(0x%x, 0x%x, %s, %s, %d, %d)" % (
    mmap_addr, mmap_length, mmap_prot_mapping(mmap_prot), mmap_flag_mapping(mmap_flags), mmap_fd, mmap_pgoffset))

    # FIXME
    # this is ugly patch, we might need to get value from elf parse,
    # is32bit or is64bit value not by arch
    MAP_ANONYMOUS = 32

    if (ql.archtype== QL_ARCH.ARM64) or (ql.archtype== QL_ARCH.X8664):
        mmap_fd = ql.unpack64(ql.pack64(mmap_fd))

    elif (ql.archtype== QL_ARCH.MIPS):
        mmap_fd = ql.unpack32s(ql.mem.read(mmap_fd, 4))
        mmap_pgoffset = ql.unpack32(ql.mem.read(mmap_pgoffset, 4))
        MAP_ANONYMOUS=2048

    else:
        mmap_fd = ql.unpack32s(ql.pack32(mmap_fd))

    mmap_base = mmap_addr
    need_mmap = True

    # initial ql.loader.mmap_address
    if mmap_addr == 0:
        mmap_base = ql.loader.mmap_address
        ql.loader.mmap_address = mmap_base + ((mmap_length + 0x1000 - 1) // 0x1000) * 0x1000
    elif ql.mem.is_mapped(mmap_addr, mmap_length):
        need_mmap = False

    ql.dprint(D_INFO, "[+] log mmap - return addr : " + hex(mmap_base))
    ql.dprint(D_INFO, "[+] log mmap - addr range  : " + hex(mmap_base) + ' - ' + hex(
        mmap_base + ((mmap_length + 0x1000 - 1) // 0x1000) * 0x1000))

    # initialized mapping
    if need_mmap:
        ql.dprint(D_INFO, "[+] log mmap - mapping needed")
        try:
            ql.mem.map(mmap_base, ((mmap_length + 0x1000 - 1) // 0x1000) * 0x1000, info="[syscall_mmap]")
        except:
            raise QlMemoryMappedError("[!] mapping needed but fail")
 
    ql.dprint(D_INFO, "[+] mmap_base 0x%x  length 0x%x" %(mmap_base, (((mmap_length + 0x1000 - 1) // 0x1000) * 0x1000)))
    
    # FIXME: MIPS32 Big Endian
    try:
        ql.mem.write(mmap_base, b'\x00' * (((mmap_length + 0x1000 - 1) // 0x1000) * 0x1000))
    except:
        pass  
    
    if ((mmap_flags & MAP_ANONYMOUS) == 0) and mmap_fd < 256 and ql.os.fd[mmap_fd] != 0:
        ql.os.fd[mmap_fd].lseek(mmap_pgoffset)
        data = ql.os.fd[mmap_fd].read(mmap_length)
        mem_info = str(ql.os.fd[mmap_fd].name)
        ql.os.fd[mmap_fd]._is_map_shared = True
        ql.os.fd[mmap_fd]._mapped_offset = mmap_pgoffset

        ql.dprint(D_INFO, "[+] log mem wirte : " + hex(len(data)))
        ql.dprint(D_INFO, "[+] log mem mmap  : " + mem_info)
        ql.mem.add_mapinfo(mmap_base, mmap_base + (((mmap_length + 0x1000 - 1) // 0x1000) * 0x1000), mem_p = UC_PROT_ALL, mem_info = "[mmap] " + mem_info)
        ql.mem.write(mmap_base, data)
        

    ql.nprint("mmap(0x%x, 0x%x, 0x%x, 0x%x, %d, %d) = 0x%x" % (mmap_addr, mmap_length, mmap_prot, mmap_flags,
                                                               mmap_fd, mmap_pgoffset, mmap_base))
    regreturn = mmap_base
    ql.dprint(D_INFO, "[+] mmap_base is 0x%x" % regreturn)

    ql.os.definesyscall_return(regreturn)


def ql_syscall_mmap2(ql, mmap2_addr, mmap2_length, mmap2_prot, mmap2_flags, mmap2_fd, mmap2_pgoffset):
    # this is ugly patch, we might need to get value from elf parse,
    # is32bit or is64bit value not by arch

    MAP_ANONYMOUS=32

    if (ql.archtype== QL_ARCH.ARM64) or (ql.archtype== QL_ARCH.X8664):
        mmap2_fd = ql.unpack64(ql.pack64(mmap2_fd))

    elif (ql.archtype== QL_ARCH.MIPS):
        mmap2_fd = ql.unpack32s(ql.mem.read(mmap2_fd, 4))
        mmap2_pgoffset = ql.unpack32(ql.mem.read(mmap2_pgoffset, 4)) * 4096
        MAP_ANONYMOUS=2048
    else:
        mmap2_fd = ql.unpack32s(ql.pack32(mmap2_fd))
        mmap2_pgoffset = mmap2_pgoffset * 4096

    mmap_base = mmap2_addr
    need_mmap = True

    if mmap2_addr == 0:
        mmap_base = ql.loader.mmap_address
        ql.loader.mmap_address = mmap_base + ((mmap2_length + 0x1000 - 1) // 0x1000) * 0x1000
    elif mmap2_addr !=0 and ql.mem.is_mapped(mmap2_addr, mmap2_length):
        need_mmap = False

    ql.dprint(D_INFO, "[+] log mmap2 - mmap2(0x%x, 0x%x, 0x%x, 0x%x, %d, %d)" % (
    mmap2_addr, mmap2_length, mmap2_prot, mmap2_flags, mmap2_fd, mmap2_pgoffset))
    ql.dprint(D_INFO, "[+] log mmap2 - mmap2(0x%x, 0x%x, %s, %s, %d, %d)" % (
    mmap2_addr, mmap2_length, mmap_prot_mapping(mmap2_prot), mmap_flag_mapping(mmap2_flags), mmap2_fd, mmap2_pgoffset))
    ql.dprint(D_INFO, "[+] log mmap2 - return addr : " + hex(mmap_base))
    ql.dprint(D_INFO, "[+] log mmap2 - addr range  : " + hex(mmap_base) + ' - ' + hex(
        mmap_base + ((mmap2_length + 0x1000 - 1) // 0x1000) * 0x1000))

    if need_mmap:
        ql.dprint(D_INFO, "[+] log mmap2 - mapping needed")
        try:
            ql.mem.map(mmap_base, ((mmap2_length + 0x1000 - 1) // 0x1000) * 0x1000, info="[syscall_mmap2]")
        except:
            ql.mem.show_mapinfo()
            raise

    ql.mem.write(mmap_base, b'\x00' * (((mmap2_length + 0x1000 - 1) // 0x1000) * 0x1000))

    if ((mmap2_flags & MAP_ANONYMOUS) == 0) and mmap2_fd < 256 and ql.os.fd[mmap2_fd] != 0:
        ql.os.fd[mmap2_fd].lseek(mmap2_pgoffset)
        data = ql.os.fd[mmap2_fd].read(mmap2_length)
        mem_info = str(ql.os.fd[mmap2_fd].name)
        ql.os.fd[mmap2_fd]._is_map_shared = True
        ql.os.fd[mmap2_fd]._mapped_offset = mmap2_pgoffset

        ql.dprint(D_INFO, "[+] log mem write : " + hex(len(data)))
        ql.dprint(D_INFO, "[+] log mem mmap2  : " + mem_info)
        ql.mem.add_mapinfo(mmap_base,  mmap_base + (((mmap2_length + 0x1000 - 1) // 0x1000) * 0x1000), mem_p = UC_PROT_ALL, mem_info = "[mmap2] " + mem_info)
        ql.mem.write(mmap_base, data)

    ql.nprint("mmap2(0x%x, 0x%x, 0x%x, 0x%x, %d, %d) = 0x%x" % (mmap2_addr, mmap2_length, mmap2_prot, mmap2_flags, mmap2_fd, mmap2_pgoffset, mmap_base))

    regreturn = mmap_base
    ql.dprint(D_INFO, "[+] mmap2_base is 0x%x" % regreturn)

    ql.os.definesyscall_return(regreturn)
