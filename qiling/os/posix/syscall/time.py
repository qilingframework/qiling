#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os
import time
import gevent

from qiling import Qiling

def ql_syscall_time(ql: Qiling):
    return int(time.time())

def __sleep_common(ql: Qiling, req: int, rem: int) -> int:
    n = ql.pointersize

    tv_sec = ql.unpack(ql.mem.read(req, n))
    tv_sec += ql.unpack(ql.mem.read(req + n, n)) / 1000000000

    if ql.os.thread_management:
        def _sched_sleep(cur_thread):
            gevent.sleep(tv_sec)

        ql.emu_stop()
        ql.os.thread_management.cur_thread.sched_cb = _sched_sleep

        # FIXME: this seems to be incomplete
        th = ql.os.thread_management.cur_thread
    else:
        time.sleep(tv_sec)

    return 0

def ql_syscall_clock_nanosleep_time64(ql: Qiling, clk_id: int, flags: int, req: int, rem: int):
    return __sleep_common(ql, req, rem)

def ql_syscall_nanosleep(ql: Qiling, req: int, rem: int):
    return __sleep_common(ql, req, rem)

def ql_syscall_clock_nanosleep(ql: Qiling, clockid: int, flags: int, req: int, rem: int):
    return __sleep_common(ql, req, rem)

def ql_syscall_setitimer(ql: Qiling, which: int, new_value: int, old_value: int):
    # TODO:The system provides each process with three interval timers, each decrementing in a distinct time domain.
    # When any timer expires, a signal is sent to the process, and the timer (potentially) restarts.
    # But I haven’t figured out how to send a signal yet.

    return 0

def ql_syscall_times(ql: Qiling, tbuf: int):
    times = os.times()

    if tbuf:
        fields = (times.user, times.system, times.children_user, times.children_system)

        ql.mem.write(tbuf, b''.join(ql.pack32(int(f * 1000)) for f in fields))

    return int(times.elapsed * 100)
