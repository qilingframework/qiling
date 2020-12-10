#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import os, time, logging
from pathlib import Path

from unicorn.unicorn import UcError
import gevent
from gevent import Greenlet

from unicorn.mips_const import *
from unicorn.arm_const import *

from qiling.utils import FMT_STR
from qiling.os.thread import *
from qiling.arch.x86_const import *
from qiling.const import *
from qiling.os.const import *


from abc import ABC, abstractmethod


LINUX_THREAD_ID = 2000

def new_thread_id():
    global LINUX_THREAD_ID
    old = LINUX_THREAD_ID
    LINUX_THREAD_ID += 1
    return old

class QlLinuxThread(QlThread):
# static member for generate unique thread id.
    

    def __init__(self, ql, start_address = 0, context = None, set_child_tid_addr = None):
        super(QlLinuxThread, self).__init__(ql)
        self._thread_id = new_thread_id()
        self._saved_context = context
        self._ql = ql
        self._exit_point = self.ql.os.exit_point
        self._start_address = start_address
        self._status = THREAD_STATUS_RUNNING
        self._return_val = 0
        self._current_path = ql.os.current_path
        self._log_file_fd = None
        self._sched_cb = None

        if self.ql.log_split:
            _logger = logging.getLogger(f"thread{self.id}")
            _logger.propagate = False
            if self.ql.log_dir is not None and self.ql.log_dir != "":
                handler = logging.FileHandler(Path(self.ql.log_dir) / f"{self.ql.targetname + self.ql.append}_{self.id}.qlog")
                handler.setFormatter(logging.Formatter(FMT_STR))
                _logger.addHandler(handler)
            
            self._log_file_fd = _logger
        else:
            self._log_file_fd = logging.getLogger()

        # For each thread, the kernel maintains two attributes (addresses)
        # called set_child_tid and clear_child_tid.  These two attributes
        # contain the value NULL by default.

        # set_child_tid
        #         If a thread is started using clone(2) with the
        #         CLONE_CHILD_SETTID flag, set_child_tid is set to the value
        #         passed in the ctid argument of that system call.

        #         When set_child_tid is set, the very first thing the new thread
        #         does is to write its thread ID at this address.

        # clear_child_tid
        #         If a thread is started using clone(2) with the
        #         CLONE_CHILD_CLEARTID flag, clear_child_tid is set to the value
        #         passed in the ctid argument of that system call.

        # The system call set_tid_address() sets the clear_child_tid value for
        # the calling thread to tidptr.

        # When a thread whose clear_child_tid is not NULL terminates, then, if
        # the thread is sharing memory with other threads, then 0 is written at
        # the address specified in clear_child_tid and the kernel performs the
        # following operation:

        #     futex(clear_child_tid, FUTEX_WAKE, 1, NULL, NULL, 0);

        # The effect of this operation is to wake a single thread that is
        # performing a futex wait on the memory location.  Errors from the
        # futex wake operation are ignored.

        # Source: Linux Man Page

        self._set_child_tid_address = set_child_tid_addr
        self._clear_child_tid_address = None

        self._robust_list_head_ptr = None
        self._robust_list_head_len = None

        if self._set_child_tid_address != None:
            self.ql.mem.write(self._set_child_tid_address, ql.pack32(self.id))

    @property
    def ql(self):
        return self._ql
    
    @ql.setter
    def ql(self, q):
        self._ql = q

    @property
    def saved_context(self):
        return self._saved_context

    @saved_context.setter
    def saved_context(self, ctx):
        self._saved_context = ctx

    @property
    def exit_point(self):
        return self._exit_point
    
    @exit_point.setter
    def exit_point(self, ep):
        self._exit_point = ep
    
    @property
    def start_address(self):
        return self._start_address
    
    @start_address.setter
    def start_address(self, sa):
        self._start_address = sa

    @property
    def status(self):
        return self._status
    
    @status.setter
    def status(self, s):
        self._status = s

    @property
    def return_val(self):
        return self._return_val

    @return_val.setter
    def return_val(self, rv):
        self._return_val = rv

    @property
    def current_path(self):
        return self._current_path

    @current_path.setter
    def current_path(self, cp):
        self._current_path = cp

    @property
    def log_file_fd(self):
        return self._log_file_fd

    @log_file_fd.setter
    def log_file_fd(self, lfd):
        self._log_file_fd = lfd

    @property
    def id(self):
        return self._thread_id

    def __hash__(self):
        return self.id
    
    def __str__(self):
        return f"[Thread {self.id}]"

    @property
    def set_child_tid_address(self):
        return self._set_child_tid_address
    
    @set_child_tid_address.setter
    def set_child_tid_address(self, addr):
        self._set_child_tid_address = addr
    
    @property
    def clear_child_tid_address(self):
        return self._clear_child_tid_address

    @clear_child_tid_address.setter
    def clear_child_tid_address(self, addr):
        self._clear_child_tid_address = addr
    
    @property
    def robust_list_head_ptr(self):
        return self._robust_list_head_ptr
    
    @robust_list_head_ptr.setter
    def robust_list_head_ptr(self, p):
        self._robust_list_head_ptr = p
    
    @property
    def robust_list_head_len(self):
        return self._robust_list_head_len
    
    @robust_list_head_len.setter
    def robust_list_head_len(self, l):
        self._robust_list_head_len = l

    @property
    def sched_cb(self):
        return self._sched_cb
    
    @sched_cb.setter
    def sched_cb(self, cb):
        self._sched_cb = cb

    def _default_sched_cb(self):
        # Give up control.
        gevent.sleep(0)

    def _run(self):
        # Some random notes for myself:
        # Implement details:
        #    The thread execution is divided in to two contexts:
        #        - Unicorn context.
        #        - Non-Unicorn context.
        #    Within both contexts, our program is single thread.
        #
        #    The only fail safe: **Never give up control in Unicorn context.**
        #    
        #    In Unicorn context, in other words, in Unicorn callbacks, we do:
        #        - Implement non-blocking syscalls directly.
        #        - Prepare sched_cb for non-unicorn context.
        #
        #    In Non-Unicorn context.
        #    In this context, we do:
        #        - Call gevent functions to switch threads.
        #        - Forward blocking syscalls to gevent.
        while self.status != THREAD_STATUS_TERMINATED:
            # Restore the context of the currently executing thread and set tls
            self.restore()

            # Run and log the run event
            self.start_address = self.ql.arch.get_pc()
            self.sched_cb = QlLinuxThread._default_sched_cb
            
            logging.debug(f"[Thread {self.get_id()}] scheduled.")
            self.status = THREAD_STATUS_RUNNING
            self.ql.os.thread_management.cur_thread = self
            try:
                # Known issue for timeout: https://github.com/unicorn-engine/unicorn/issues/1355
                self.ql.emu_start(self.start_address, self.exit_point, count=3000)
            except UcError:
                print(self.ql._hook)
                self.ql.os.emu_error()
                raise
            if self.ql.arch.get_pc() == self.exit_point:
                self.stop()
                break

            self.save()
            # Note that this callback may be set by UC callbacks.
            # Some thought on this design:
            #      1. Never give up control during a UC callback.
            #      2. emu_stop only sends a signal to unicorn which won't stop it immediately.
            #      3. According to 1, never call gevent functions in UC callbacks.
            logging.debug(f"[Thread {self.get_id()}] calls sched_cb: {self.sched_cb}")
            self.sched_cb(self)

    # Depreciated.
    def get_id(self):
        return self.id

    @abstractmethod
    def save(self):
        pass

    @abstractmethod
    def restore(self):
        pass

    @abstractmethod
    def clone_thread_tls(self, tls_addr):
        pass

    def suspend(self):
        self.save()

    # TODO: Rename
    def save_context(self):
        self.saved_context = self.ql.arch.context_save()

    def restore_context(self):
        self.ql.arch.context_restore(self.saved_context)

    def set_start_address(self, addr):
        # We can't modify UcContext directly.
        old_context = self.ql.arch.context_save()
        self.restore_context()
        self.ql.reg.arch_pc = addr
        self.save_context()
        self.ql.arch.context_restore(old_context)

    def set_clear_child_tid_addr(self, addr):
        self.clear_child_tid_address = addr

    def _on_stop(self):
        # CLONE_CHILD_CLEARTID (since Linux 2.5.49)
        #       Clear (zero) the child thread ID at the location pointed to by
        #       child_tid (clone()) or cl_args.child_tid (clone3()) in child
        #       memory when the child exits, and do a wakeup on the futex at
        #       that address.  The address involved may be changed by the
        #       set_tid_address(2) system call.  This is used by threading
        #       libraries.

        # Source: Linux Man Page

        if self.clear_child_tid_address is not None:
            logging.debug(f"[Thread {self.get_id()}] Perform CLONE_CHILD_CLEARTID at {hex(self.clear_child_tid_address)}")
            self.ql.mem.write(self.clear_child_tid_address, self.ql.pack32(0))
            wakes = self.ql.os.futexm.get_futex_wake_list(self.ql, self.clear_child_tid_address, 1)
            self.clear_child_tid_address = None
            # When the thread is to stop, we don't have chance for next sched_cb, so
            # we notify the thread directly.
            for t, e in wakes:
                logging.debug(f"[Thread {self.get_id()}] Notify [Thread {t.get_id()}].")
                e.set()

    # This function should called outside unicorn callback.
    def stop(self):
        self._on_stop()
        self.status = THREAD_STATUS_TERMINATED

    def is_stop(self):
        #return self.status == THREAD_STATUS_TERMINATED
        return self.dead

    def is_running(self):
        return not self.dead

    def is_blocking(self):
        return self.status == THREAD_STATUS_BLOCKING

    def update_global_thread_id(self):
        QlLinuxThread.LINUX_THREAD_ID = os.getpid()


class QlLinuxX86Thread(QlLinuxThread):
    """docstring for X86Thread"""
    def __init__(self, ql, start_address = 0, context = None, set_child_tid_addr = None):
        super(QlLinuxX86Thread, self).__init__(ql, start_address, context, set_child_tid_addr)
        self.tls = bytes(b'\x00' * (8 * 3))

    def clone_thread_tls(self, tls_addr):
        old_tls = bytes(self.ql.os.gdtm.get_gdt_buf(12, 14 + 1))

        self.ql.os.gdtm.set_gdt_buf(12, 14 + 1, self.tls)

        u_info = self.ql.mem.read(tls_addr, 4 * 4)
        index = self.ql.unpack32s(u_info[0 : 4])
        base = self.ql.unpack32(u_info[4 : 8])
        limit = self.ql.unpack32(u_info[8 : 12])

        if index == -1:
            index = self.ql.os.gdtm.get_free_idx(12)

        if index == -1 or index < 12 or index > 14:
            raise
        else:
            self.ql.os.gdtm.register_gdt_segment(index, base, limit, QL_X86_A_PRESENT | QL_X86_A_DATA | QL_X86_A_DATA_WRITABLE | QL_X86_A_PRIV_3 | QL_X86_A_DIR_CON_BIT, QL_X86_S_GDT | QL_X86_S_PRIV_3)
            self.ql.mem.write(tls_addr, self.ql.pack32(index))

        self.tls = bytes(self.ql.os.gdtm.get_gdt_buf(12, 14 + 1))
        self.ql.os.gdtm.set_gdt_buf(12, 14 + 1, old_tls)

    def save(self):
        self.save_context()
        self.tls = bytes(self.ql.os.gdtm.get_gdt_buf(12, 14 + 1))

    def restore(self):
        self.restore_context()
        self.ql.os.gdtm.set_gdt_buf(12, 14 + 1, self.tls)
        self.ql.reg.gs = self.ql.reg.gs
        self.ql.reg.fs = self.ql.reg.fs

class QlLinuxX8664Thread(QlLinuxThread):
    """docstring for X8664Thread"""
    def __init__(self, ql, start_address = 0, context = None, set_child_tid_addr = None):
        super(QlLinuxX8664Thread, self).__init__(ql,start_address, context, set_child_tid_addr)
        self.tls = 0

    def clone_thread_tls(self, tls_addr):
        self.tls = tls_addr

    def save(self):
        self.save_context()
        self.tls = self.ql.reg.msr(FSMSR)

    def restore(self):
        self.restore_context()
        self.ql.reg.msr(FSMSR, self.tls)

class QlLinuxMIPS32Thread(QlLinuxThread):
    """docstring for QlLinuxMIPS32Thread"""
    def __init__(self, ql, start_address = 0, context = None, set_child_tid_addr = None):
        super(QlLinuxMIPS32Thread, self).__init__(ql, start_address, context, set_child_tid_addr)
        self.tls = 0


    def clone_thread_tls(self, tls_addr):
        self.tls = tls_addr


    def save(self):
        self.save_context()
        self.tls = self.ql.reg.cp0_userlocal 


    def restore(self):
        self.restore_context()
        CONFIG3_ULR = (1 << 13)
        self.ql.reg.cp0_config3 = CONFIG3_ULR
        self.ql.reg.cp0_userlocal = self.tls


class QlLinuxARMThread(QlLinuxThread):
    """docstring for QlLinuxARMThread"""
    def __init__(self, ql, start_address = 0, context = None, set_child_tid_addr = None):
        super(QlLinuxARMThread, self).__init__(ql, start_address, context, set_child_tid_addr)
        self.tls = 0


    def clone_thread_tls(self, tls_addr):
        self.tls = tls_addr


    def save(self):
        self.save_context()
        self.tls = self.ql.reg.c13_c0_3


    def restore(self):
        self.restore_context()
        self.ql.reg.c13_c0_3 = self.tls


class QlLinuxARM64Thread(QlLinuxThread):
    """docstring for QlLinuxARM64Thread"""
    def __init__(self, ql, start_address = 0, context = None, set_child_tid_addr = None):
        super(QlLinuxARM64Thread, self).__init__(ql, start_address, context, set_child_tid_addr)
        self.tls = 0

    def clone_thread_tls(self, tls_addr):
        self.tls = tls_addr

    def save(self):
        self.save_context()
        self.tls = self.ql.reg.tpidr_el0

    def restore(self):
        self.restore_context()
        self.ql.reg.tpidr_el0 = self.tls

class QlLinuxThreadManagement:
    def __init__(self, ql):
        self.ql = ql
        self.threads = set()
        self.runing_time = 0
        self._main_thread = None
        self._cur_thread = None

    # cur_thread is only guaranteed to be correct in unicorn callbacks context.
    @property
    def cur_thread(self):
        return self._cur_thread

    @cur_thread.setter
    def cur_thread(self, ct):
        self._cur_thread = ct

    @property
    def main_thread(self):
        return self._main_thread
    
    @main_thread.setter
    def main_thread(self, mt):
        self._main_thread = mt

    def stop_thread(self, t):
        t.stop()
        if t in self.threads:
            self.threads.remove(t)
        # Exit the world.
        if t == self.main_thread:
            self.stop()
    
    # Stop the world, urge all threads to stop immediately.
    def stop(self):
        logging.debug("[Thread Manager] Stop the world.")
        self.ql.emu_stop()
        for t in self.threads:
            gevent.kill(t)

    def run(self):
        # If we get exceptions from gevent here, it means a critical bug related to multithread.
        # Please fire an issue if you encounter an exception from gevent.
        gevent.joinall([self.main_thread])

