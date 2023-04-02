#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.posix.const import *

from .shm import *


def ql_syscall_ipc(ql: Qiling, call: int, first: int, second: int, third: int, ptr: int, fifth: int):
    version = call >> 16  # hi word
    call &= 0xffff        # lo word

    # FIXME: this is an incomplete implementation.
    # see: https://elixir.bootlin.com/linux/v5.19.17/source/ipc/syscall.c

    def __call_shmat(*args: int) -> int:
        if version == 1:
            return -1   # EINVAL

        return ql_syscall_shmget(ql, args[0], args[3], args[1])

    def __call_shmget(*args: int) -> int:
        return ql_syscall_shmget(ql, args[0], args[1], args[2])

    ipc_call = {
        SHMAT:  __call_shmat,
        SHMGET: __call_shmget
    }

    if call not in ipc_call:
        return -1   # ENOSYS

    return ipc_call[call](first, second, third, ptr, fifth)


__all__ = [
    'ql_syscall_ipc'
]
