#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
import gevent
def ql_syscall_rt_sigaction(ql: Qiling, signum: int, act: int, oldact: int):
    if oldact:
        arr = ql.os.sigaction_act[signum] or [0] * 5
        data = b''.join(ql.pack32(key) for key in arr)

        ql.mem.write(oldact, data)

    if act:
        ql.os.sigaction_act[signum] = [ql.mem.read_ptr(act + 4 * i, 4) for i in range(5)]

    return 0


def ql_syscall_rt_sigprocmask(ql: Qiling, how: int, nset: int, oset: int, sigsetsize: int):
    # SIG_BLOCK = 0x0
    # SIG_UNBLOCK = 0x1
    ql.os.sigsetsize = sigsetsize
    
    return 0

def ql_syscall_rt_sigsuspend(ql: Qiling, mask: int):
    def _sched_sigsupend(cur_thread):
        find_available_signal = 0
        if not ql.os.sigsetsize:
            ql.log.debug("sigset_size not be initialization")
            return -1
        mask_data = cur_thread.ql.mem.read(mask, ql.os.sigsetsize)
        
        while 1:
            signal_index = 0
            while signal_index < len(cur_thread.ql.os.signal_list):
                signal = cur_thread.ql.os.signal_list[signal_index]
                signal = signal-1
                signal_block_flag = mask_data[int(signal/8)] &(1<<signal)
                if not signal_block_flag:
                    ql.log.debug("find signal(%d) not be blocked" % (signal+1))
                    
                    del cur_thread.ql.os.signal_list[signal_index]
                    find_available_signal = 1
                    break
                signal_index += 1
            if find_available_signal:
                break
            else:
                gevent.sleep(0)
            
        return 0  
    ql.os.thread_management.cur_thread.sched_cb = _sched_sigsupend
    ql.emu_stop()
def ql_syscall_signal(ql: Qiling, sig: int, sighandler: int):
    return 0
