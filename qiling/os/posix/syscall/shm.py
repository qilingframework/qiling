#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn.unicorn_const import UC_PROT_WRITE, UC_PROT_READ

from qiling import Qiling
from qiling.exception import QlOutOfMemory
from qiling.os.posix.const import *
from qiling.os.posix.posix import QlShmId


def ql_syscall_shmget(ql: Qiling, key: int, size: int, shmflg: int):

    def __create_shm(size: int, flags: int) -> int:
        perms = flags & ((1 << 9) - 1)

        posix_to_uc = (
            (SHM_W, UC_PROT_WRITE),
            (SHM_R, UC_PROT_READ)
        )

        # convert posix permissions to unicorn memory access bits
        uc_perms = sum(u_perm for p_perm, u_perm in posix_to_uc if perms & p_perm)

        # determine size alignment: either normal or huge page
        if flags & SHM_HUGETLB:
            shiftsize = (flags >> HUGETLB_FLAG_ENCODE_SHIFT) & HUGETLB_FLAG_ENCODE_MASK
            pagesize = (1 << shiftsize)
        else:
            pagesize = ql.mem.pagesize

        if len(ql.os.shm) < SHMMNI:
            shm_size = ql.mem.align_up(size, pagesize)

            try:
                shm_addr = ql.mem.find_free_space(shm_size, ql.loader.mmap_address, align=pagesize)
            except QlOutOfMemory:
                return -1   # ENOMEM
            else:
                ql.mem.map(shm_addr, shm_size, uc_perms, '[shm]')

            # for simplicity, the shm key is defined to be its base address
            shm_key = shm_addr

            ql.os.shm[shm_key] = QlShmId(shm_size, ql.os.uid, ql.os.gid, perms)

        else:
            return -1   # ENOSPC

        return shm_key

    # create new shared memory segment
    if key == IPC_PRIVATE:
        key = __create_shm(size, shmflg)

    # a shm with the specified key exists
    elif key in ql.os.shm:
        # user asked to create a new one?
        if shmflg & (IPC_CREAT | IPC_EXCL):
            return -1   # EEXIST

        shmid = ql.os.shm[key]

        # check whether the user has permissions to access this shm
        # FIXME: should probably use ql.os.cuid instead, but we don't support it yet
        if (ql.os.uid == shmid.uid) and (shmid.mode & (SHM_W | SHM_R)):
            return key

        else:
            return -1   # EACCES

    # a shm with the specified key does not exist
    else:
        # user asked to create a new one?
        if shmflg & IPC_CREAT:
            key = __create_shm(size, shmflg)

        else:
            return -1   # ENOENT

    return key


def ql_syscall_shmat(ql: Qiling, shmid: int, shmaddr: int, shmflg: int):
    if shmid not in ql.os.shm:
        return -1   # EINVAL

    if shmaddr == 0:
        # system may choose any suitable page-aligned address. since existing segments are
        # guaranteed to be aligned and key is defined to be shm base address, we can just
        # use the key
        addr = shmid

    elif shmflg & SHM_RND:
        # note: should align to SHMLBA, but usually its value is just a page
        addr = ql.mem.align(shmaddr)

    else:
        if shmaddr & (ql.mem.pagesize - 1):
            return -1   # EINVAL

        addr = shmaddr

    return addr


__all__ = [
    'ql_syscall_shmget',
    'ql_syscall_shmat'
]
