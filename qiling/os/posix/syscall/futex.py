#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling

def ql_syscall_set_robust_list(ql: Qiling, head_ptr: int, head_len: int):
    if ql.multithread:
        ql.os.thread_management.cur_thread.robust_list_head_ptr = head_ptr
        ql.os.thread_management.cur_thread.robust_list_head_len = head_len

    return 0


def ql_syscall_futex(ql: Qiling, uaddr: int, op: int, val: int, timeout: int, uaddr2: int, val3: int):
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

    if op & (FUTEX_PRIVATE_FLAG - 1) == FUTEX_WAIT:
        # def futex_wait_addr(ql, th, arg):
        #     addr, val = arg
        #     return ql.unpack32(ql.mem.read(addr, 4)) == val

        regreturn = ql.os.futexm.futex_wait(ql, uaddr, ql.os.thread_management.cur_thread, val)

    elif op & (FUTEX_PRIVATE_FLAG - 1) == FUTEX_WAIT_BITSET:
        regreturn = ql.os.futexm.futex_wait(ql, uaddr, ql.os.thread_management.cur_thread, val, val3)

    elif op & (FUTEX_PRIVATE_FLAG - 1) == FUTEX_WAKE:
        regreturn = ql.os.futexm.futex_wake(ql, uaddr,ql.os.thread_management.cur_thread, val)

    elif op & (FUTEX_PRIVATE_FLAG - 1) == FUTEX_WAKE_BITSET:
        regreturn = ql.os.futexm.futex_wake(ql, uaddr,ql.os.thread_management.cur_thread, val, val3)

    else:
        ql.log.debug(f'futex({uaddr:x}, {op:d}, {val:d}) = ?')
        ql.emu_stop()
        #ql.os.thread_management.cur_thread.stop()
        #ql.os.thread_management.cur_thread.stop_event = THREAD_EVENT_EXIT_GROUP_EVENT
        regreturn = 0

    return regreturn
