#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn.unicorn_const import UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC

from qiling import Qiling
from qiling.const import QL_ARCH
from qiling.exception import QlMemoryMappedError
from qiling.os.posix.const import *
from qiling.os.posix.shm import QlShmId


def ql_syscall_shmget(ql: Qiling, key: int, size: int, shmflg: int):

    def __create_shm(key: int, size: int, flags: int) -> int:
        """Create a new shared memory segment for the specified key.

        Returns: shmid of the newly created segment, -1 if an error has occured
        """

        if len(ql.os.shm) >= SHMMNI:
            return -1   # ENOSPC

        mode = flags & ((1 << 9) - 1)

        # determine size alignment: either normal or huge page
        if flags & SHM_HUGETLB:
            shiftsize = (flags >> HUGETLB_FLAG_ENCODE_SHIFT) & HUGETLB_FLAG_ENCODE_MASK
            alignment = (1 << shiftsize)
        else:
            alignment = ql.mem.pagesize

        shm_size = ql.mem.align_up(size, alignment)

        shmid = ql.os.shm.add(QlShmId(key, ql.os.uid, ql.os.gid, mode, shm_size))

        ql.log.debug(f'created a new shm: key = {key:#x}, mode = 0{mode:o}, size = {shm_size:#x}. assigned id: {shmid:#x}')

        return shmid

    # create new shared memory segment
    if key == IPC_PRIVATE:
        shmid = __create_shm(key, size, shmflg)

    else:
        shmid, shm = ql.os.shm.get_by_key(key)

        # a shm with the specified key does not exist
        if shm is None:
            # the user asked to create a new one?
            if shmflg & IPC_CREAT:
                shmid = __create_shm(key, size, shmflg)

            else:
                return -1   # ENOENT

        # a shm with the specified key exists
        else:
            # the user asked to create a new one?
            if shmflg & (IPC_CREAT | IPC_EXCL):
                return -1   # EEXIST

            # check whether the user has permissions to access this shm
            # FIXME: should probably use ql.os.cuid instead, but we don't support it yet
            if (ql.os.uid == shm.uid) and (shm.mode & (SHM_W | SHM_R)):
                return shmid

            else:
                return -1   # EACCES

    return shmid


def ql_syscall_shmat(ql: Qiling, shmid: int, shmaddr: int, shmflg: int):
    shm = ql.os.shm.get_by_id(shmid)

    # a shm with the specified key does not exist
    if shm is None:
        return -1   # EINVAL

    if shmaddr == 0:
        # system may choose any suitable page-aligned address
        attaddr = ql.mem.find_free_space(shm.segsz, ql.loader.mmap_address)

    elif shmflg & SHM_RND:
        # select the appropriate SHMLBA value, based on the platform
        shmlba = {
            QL_ARCH.MIPS:  0x40000,
            QL_ARCH.ARM:   ql.mem.pagesize * 4,
            QL_ARCH.ARM64: ql.mem.pagesize * 4,
            QL_ARCH.X86:   ql.mem.pagesize,
            QL_ARCH.X8664: ql.mem.pagesize
        }

        # align the address specified by shmaddr to platform SHMLBA
        attaddr = ql.mem.align(shmaddr, shmlba[ql.arch.type])

    else:
        # shmaddr is expected to be aligned
        if shmaddr & (ql.mem.pagesize - 1):
            return -1   # EINVAL

        attaddr = shmaddr

    perms = UC_PROT_READ

    if shmflg & SHM_RDONLY == 0:
        perms |= UC_PROT_WRITE

    if shmflg & SHM_EXEC:
        perms |= UC_PROT_EXEC

    # user asked to attached the seg as readable; is it allowed?
    if (perms & UC_PROT_READ) and not (shm.mode & SHM_R):
        return -1   # EACCES

    # user asked to attached the seg as writable; is it allowed?
    if (perms & UC_PROT_WRITE) and not (shm.mode & SHM_W):
        return -1   # EACCES

    # TODO: if segment is already attached, there is no need to map another memory for it.
    # if we do, data changes will not be reflected between the segment attachments. we could
    # use a mmio map for additional attachments, and have writes and reads directed to the
    # first attachment mapping

    try:
        # attach the segment at shmaddr
        ql.mem.map(attaddr, shm.segsz, perms, '[shm]')
    except QlMemoryMappedError:
        return -1   # EINVAL

    # track attachment
    shm.attach.append(attaddr)

    ql.log.debug(f'shm {shmid:#x} attached at {attaddr:#010x}')

    return attaddr


def ql_syscall_shmdt(ql: Qiling, shmaddr: int):
    shm = ql.os.shm.get_by_attaddr(shmaddr)

    if shm is None:
        return -1   # EINVAL

    shm.attach.remove(shmaddr)

    return 0


__all__ = [
    'ql_syscall_shmget',
    'ql_syscall_shmdt',
    'ql_syscall_shmat'
]
