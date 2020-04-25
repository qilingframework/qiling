#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

from qiling.const import *
from qiling.os.linux.thread import *
from qiling.const import *
from qiling.os.posix.filestruct import *
from qiling.os.filestruct import *
from qiling.os.posix.const_mapping import *
from qiling.exception import *

def ql_syscall_time(ql, *args, **kw):
    regreturn = int(time.time())
    ql.nprint("time() = %d" % regreturn)
    ql.os.definesyscall_return(regreturn)


def ql_syscall_nanosleep(ql, nanosleep_req, nanosleep_rem, *args, **kw):
    def nanosleep_block_fuc(ql, th, arg):
        st, tm = arg
        et = ql.os.thread_management.runing_time
        if et - st >= tm:
            return False
        else:
            return True

    n = ql.archbit // 8 # 4 for 32-bit , 8 for 64-bit

    tv_sec = ql.unpack(ql.mem.read(nanosleep_req, n))
    tv_sec += ql.unpack(ql.mem.read(nanosleep_req + n, n)) / 1000000000

    if ql.os.thread_management == None:
        time.sleep(tv_sec)
    else:
        ql.emu_stop()

        th = ql.os.thread_management.cur_thread
        th.blocking()
        th.set_blocking_condition(nanosleep_block_fuc, [ql.os.thread_management.runing_time, int(tv_sec * 1000000)])

    regreturn = 0
    ql.nprint("nanosleep(0x%x, 0x%x) = %d" % (nanosleep_req, nanosleep_rem, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_setitimer(ql, setitimer_which, setitimer_new_value, setitimer_old_value, *args, **kw):
    # TODO:The system provides each process with three interval timers, each decrementing in a distinct time domain.
    # When any timer expires, a signal is sent to the process, and the timer (potentially) restarts.
    # But I haven’t figured out how to send a signal yet.
    regreturn = 0
    ql.nprint("setitimer(%d, %x, %x) = %d" % (setitimer_which, setitimer_new_value, setitimer_old_value, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_times(ql, times_tbuf, *args, **kw):
    tmp_times = os.times()
    if times_tbuf != 0:
        tmp_buf = b''
        tmp_buf += ql.pack32(int(tmp_times.user * 1000))
        tmp_buf += ql.pack32(int(tmp_times.system * 1000))
        tmp_buf += ql.pack32(int(tmp_times.children_user * 1000))
        tmp_buf += ql.pack32(int(tmp_times.children_sytem * 1000))
        ql.mem.write(times_tbuf, tmp_buf)
    regreturn = int(tmp_times.elapsed * 100)
    ql.nprint('times(%x) = %d' % (times_tbuf, regreturn))
    ql.os.definesyscall_return(regreturn)


def ql_syscall_gettimeofday(ql, gettimeofday_tv, gettimeofday_tz, *args, **kw):
    tmp_time = time.time()
    tv_sec = int(tmp_time)
    tv_usec = int((tmp_time - tv_sec) * 1000000)

    if gettimeofday_tv != 0:
        ql.mem.write(gettimeofday_tv, ql.pack32(tv_sec) + ql.pack32(tv_usec))
    if gettimeofday_tz != 0:
        ql.mem.write(gettimeofday_tz, b'\x00' * 8)
    regreturn = 0
    ql.nprint("gettimeofday(%x, %x) = %d" % (gettimeofday_tv, gettimeofday_tz, regreturn))
    ql.os.definesyscall_return(regreturn)
