#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.posix.const import *

from .shm import *
from .msg import *


def ql_syscall_ipc(ql: Qiling, call: int, first: int, second: int, third: int, ptr: int, fifth: int):
    version = call >> 16  # hi word
    call &= 0xffff        # lo word

    # FIXME: this is an incomplete implementation.
    # see: https://elixir.bootlin.com/linux/v5.19.17/source/ipc/syscall.c

    def __call_shmat(*args: int) -> int:
        if version == 1:
            return -1   # EINVAL

        return ql_syscall_shmat(ql, args[0], args[3], args[1])

    def __call_shmdt(*args: int) -> int:
        return ql_syscall_shmdt(ql, args[3])

    def __call_shmget(*args: int) -> int:
        return ql_syscall_shmget(ql, args[0], args[1], args[2])
    
    def __call_msgget(*args: int) -> int:
        return ql_syscall_msgget(ql, args[0], args[1])

    def __call_msgsnd(*args: int) -> int:
        return ql_syscall_msgsnd(ql, args[0], args[3], args[1], args[2])
    
    def __call_msgrcv(*args: int) -> int:
        if version == 0:
            if args[3] == 0:
                return -1   # EINVAL

            msgp = ql.mem.read_ptr(args[3])
            msgtyp = ql.mem.read_ptr(args[3] + ql.arch.pointersize)

        else:
            msgp = args[3]
            msgtyp = args[4]

        return ql_syscall_msgrcv(ql, args[0], msgp, args[1], msgtyp, args[2])

    ipc_call = {
        SHMAT:  __call_shmat,
        SHMDT:  __call_shmdt,
        SHMGET: __call_shmget,
        MSGGET: __call_msgget,
        MSGSND: __call_msgsnd,
        MSGRCV: __call_msgrcv
    }

    if call not in ipc_call:
        return -1   # ENOSYS

    return ipc_call[call](first, second, third, ptr, fifth)


__all__ = [
    'ql_syscall_ipc'
]
