#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import os, time

from unicorn.mips_const import *
from unicorn.arm_const import *

from qiling.utils import ql_setup_logging_file, ql_setup_logger
from qiling.os.thread import *
from qiling.arch.x86_const import *
from qiling.const import *
from qiling.os.const import *


from abc import ABC, abstractmethod

TIME_MODE = 0
COUNT_MODE = 1
BBL_MODE = 2


class QlLinuxThread(QlThread):
# static member for generate unique thread id.
    LINUX_THREAD_ID = 2000

    def __init__(self, ql, thread_management = None, start_address = 0, context = None, total_time = 0, set_child_tid_addr = None):
        super(QlLinuxThread, self).__init__(ql)
        self.thread_id = QlLinuxThread.LINUX_THREAD_ID
        QlLinuxThread.LINUX_THREAD_ID += 1
        self.total_time = total_time
        self.runing_time = 0
        self.context = context
        self.ql = ql
        self.exit_point = self.ql.os.exit_point
        self.start_address = start_address
        self.status = THREAD_STATUS_RUNNING
        self.stop_event = THREAD_EVENT_INIT_VAL
        self.stop_return_val = None
        self.return_val = 0
        self.blocking_condition_fuc = None
        self.blocking_condition_arg = None
        self.thread_management = thread_management
        self.current_path = ql.os.current_path
        self.log_file_fd = None

        _logger = ql_setup_logger(str(self.thread_id)) if ql.log_split else ql_setup_logger()

        if ql.log_dir and ql.log_file != None:
            if ql.log_split:
                _logger = ql_setup_logging_file(ql.output, '%s_%s' % (ql.log_file, self.thread_id), _logger)
            else:
                _logger = ql_setup_logging_file(ql.output, ql.log_file, _logger)

        self.log_file_fd = _logger


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

        self.set_child_tid_address = set_child_tid_addr
        self.clear_child_tid_address = None

        self.robust_list_head_ptr = None
        self.robust_list_head_len = None

        if self.set_child_tid_address != None:
            self.ql.mem.write(self.set_child_tid_address, ql.pack32(self.thread_id))

    def run(self, mode, time_slice = 0, count_slice = 0, bbl_slice = 0):
        # Set the time of the current run
        if mode == TIME_MODE:
            if time_slice == 0 and self.total_time != 0:
                thread_slice = self.total_time - self.runing_time
            else:
                thread_slice = time_slice
        elif mode == COUNT_MODE:
            thread_slice = count_slice
        elif mode == BBL_MODE:
            thread_slice = bbl_slice
        else:
            raise

        # Initialize, stop event
        self.return_val = 0
        self.stop_event = THREAD_EVENT_INIT_VAL

        # Restore the context of the currently executing thread and set tls
        self.restore()

        # Run and log the run event
        s_time = int(time.time() * 1000000)
        self.start_address = self.ql.arch.get_pc()

        if mode == TIME_MODE:
            self.ql.emu_start(self.start_address, self.exit_point, timeout = thread_slice)
        elif mode == COUNT_MODE:
            self.ql.emu_start(self.start_address, self.exit_point, count = thread_slice)
        elif mode == BBL_MODE:
            self.thread_management.set_bbl_count(thread_slice)
            self.ql.emu_start(self.start_address, self.exit_point)
        else:
            raise

        e_time = int(time.time() * 1000000)

        self.runing_time += (e_time - s_time)

        if self.total_time != 0 and self.runing_time >= self.total_time:
            self.status = THREAD_STATUS_TIMEOUT

        if self.ql.arch.get_pc() == self.exit_point:
            self.stop()
            self.stop_event = THREAD_EVENT_EXIT_EVENT

        return (e_time - s_time)

    @abstractmethod
    def store(self):
        pass

    @abstractmethod
    def restore(self):
        pass

    @abstractmethod
    def clone_thread_tls(self, tls_addr):
        pass

    def suspend(self):
        self.store()

    def store_regs(self):
        self.context = self.ql.context()
        self.start_address = self.ql.arch.get_pc()

    def restore_regs(self):
        self.ql.context(self.context)

    def set_start_address(self, addr):
        old_context = self.ql.context()
        self.restore_regs()
        self.ql.reg.arch_pc = addr
        self.store_regs()
        self.ql.context(old_context)

    def set_context(self, con):
        self.context = con

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

        if self.clear_child_tid_address != None:
            self.ql.mem.write(self.clear_child_tid_address, self.ql.pack32(0))
        self.ql.os.futexm.futex_wake(self.clear_child_tid_address, 1)

    def stop(self):
        self._on_stop()
        self.status = THREAD_STATUS_TERMINATED

    def blocking(self):
        self.status = THREAD_STATUS_BLOCKING

    def running(self):
        self.status = THREAD_STATUS_RUNNING

    def is_stop(self):
        return self.status == THREAD_STATUS_TERMINATED

    def is_running(self):
        return self.status == THREAD_STATUS_RUNNING

    def is_blocking(self):
        return self.status == THREAD_STATUS_BLOCKING

    def is_timeout(self):
        return self.status == THREAD_STATUS_TIMEOUT

    def get_thread_id(self):
        return self.thread_id

    def get_return_val(self):
        return self.return_val

    def set_blocking_condition(self, bc_fuc, bc_arg = None):
        #When a thread encounters a special thing and needs to block,
        #it will call this function to determine if it needs to continue blocking.

        # Why do I need such a function, because when I am programming,
        # I will encounter functions like sleep, wait, etc.
        # If I don't do any processing, I will block the ThreadManagement if I call it directly.
        # (This is also a design flaw of mine, because I designed it as Single process).
        # When implementing system calls, you need to unpack the system calls that are blocked,
        # and check whether the conditions are met on each time slice to prevent program blocking.
        self.blocking_condition_fuc = bc_fuc
        self.blocking_condition_arg = bc_arg

    def is_continue_blocking(self):
        if self.blocking_condition_fuc == None:
            return True

        if self.blocking_condition_arg == None:
            return self.blocking_condition_fuc(self.ql, self)
        else:
            return self.blocking_condition_fuc(self.ql, self, self.blocking_condition_arg)

    def change_thread_management(self, tm):
        self.thread_management = tm

    def remaining_time(self):
        if self.total_time == 0:
            return 0
        return self.total_time - self.runing_time

    def set_exit_point(self, exit_point):
        self.exit_point = exit_point

    def new_thread_id(self):
        self.thread_id = QlLinuxThread.LINUX_THREAD_ID
        QlLinuxThread.LINUX_THREAD_ID += 1

    def update_global_thread_id(self):
        QlLinuxThread.LINUX_THREAD_ID = os.getpid()

    def set_thread_log_file(self, log_dir):
        if self.ql.log_split and log_dir != None:
            _logger = self.ql.log_file_fd
            self.log_file_fd = ql_setup_logging_file(self.ql.output, log_dir, _logger)

    def get_current_path(self):
        return self.current_path

    def set_current_path(self, path):
        self.current_path = path


class QlLinuxX86Thread(QlLinuxThread):
    """docstring for X86Thread"""
    def __init__(self, ql, thread_management = None, start_address = 0, context = None, total_time = 0, set_child_tid_addr = None):
        super(QlLinuxX86Thread, self).__init__(ql, thread_management, start_address, context, total_time, set_child_tid_addr)
        self.tls = bytes(b'\x00' * (8 * 3))

    def clone_thread_tls(self, tls_addr):
        old_tls = bytes(self.ql.os.gdtm.get_gdt_buf(12, 14 + 1))

        # FIXME : self.ql.os should be better
        self.ql.os.gdtm.set_gdt_buf(12, 14 + 1, self.tls)

        u_info = self.ql.mem.read(tls_addr, 4 * 4)
        index = self.ql.unpack32s(u_info[0 : 4])
        base = self.ql.unpack32(u_info[4 : 8])
        limit = self.ql.unpack32(u_info[8 : 12])

        if index == -1:
            # FIXME : self.ql.os should be better
            index = self.ql.os.gdtm.get_free_idx(12)

        if index == -1 or index < 12 or index > 14:
            raise
        else:
            self.ql.os.gdtm.register_gdt_segment(index, base, limit, QL_X86_A_PRESENT | QL_X86_A_DATA | QL_X86_A_DATA_WRITABLE | QL_X86_A_PRIV_3 | QL_X86_A_DIR_CON_BIT, QL_X86_S_GDT | QL_X86_S_PRIV_3)
            self.ql.mem.write(tls_addr, self.ql.pack32(index))

        # FIXME : self.ql.os should be better
        self.tls = bytes(self.ql.os.gdtm.get_gdt_buf(12, 14 + 1))
        self.ql.os.gdtm.set_gdt_buf(12, 14 + 1, old_tls)

    def store(self):
        self.store_regs()
        # FIXME : self.ql.os should be better
        self.tls = bytes(self.ql.os.gdtm.get_gdt_buf(12, 14 + 1))

    def restore(self):
        self.restore_regs()
        # FIXME : self.ql.os should be better
        self.ql.os.gdtm.set_gdt_buf(12, 14 + 1, self.tls)

class QlLinuxX8664Thread(QlLinuxThread):
    """docstring for X8664Thread"""
    def __init__(self, ql, thread_management = None, start_address = 0, context = None, total_time = 0, set_child_tid_addr = None):
        super(QlLinuxX8664Thread, self).__init__(ql, thread_management, start_address, context, total_time, set_child_tid_addr)
        self.tls = 0

    def clone_thread_tls(self, tls_addr):
        self.tls = tls_addr

    def store(self):
        self.store_regs()
        self.tls = self.ql.reg.msr(FSMSR)

    def restore(self):
        self.restore_regs()
        self.ql.reg.msr(FSMSR, self.tls)

class QlLinuxMIPS32Thread(QlLinuxThread):
    """docstring for QlLinuxMIPS32Thread"""
    def __init__(self, ql, thread_management = None, start_address = 0, context = None, total_time = 0, set_child_tid_addr = None):
        super(QlLinuxMIPS32Thread, self).__init__(ql, thread_management, start_address, context, total_time, set_child_tid_addr)
        self.tls = 0


    def clone_thread_tls(self, tls_addr):
        self.tls = tls_addr


    def store(self):
        self.store_regs()
        self.tls = self.ql.reg.cp0_userlocal 


    def restore(self):
        self.restore_regs()
        CONFIG3_ULR = (1 << 13)
        self.ql.reg.cp0_config3 = CONFIG3_ULR
        self.ql.reg.cp0_userlocal = self.tls


class QlLinuxARMThread(QlLinuxThread):
    """docstring for QlLinuxARMThread"""
    def __init__(self, ql, thread_management = None, start_address = 0, context = None, total_time = 0, set_child_tid_addr = None):
        super(QlLinuxARMThread, self).__init__(ql, thread_management, start_address, context, total_time, set_child_tid_addr)
        self.tls = 0


    def clone_thread_tls(self, tls_addr):
        self.tls = tls_addr


    def store(self):
        self.store_regs()
        self.tls = self.ql.reg.c13_c0_3


    def restore(self):
        self.restore_regs()
        self.ql.reg.c13_c0_3 = self.tls


class QlLinuxARM64Thread(QlLinuxThread):
    """docstring for QlLinuxARM64Thread"""
    def __init__(self, ql, thread_management = None, start_address = 0, context = None, total_time = 0, set_child_tid_addr = None):
        super(QlLinuxARM64Thread, self).__init__(ql, thread_management, start_address, context, total_time, set_child_tid_addr)

    def clone_thread_tls(self, tls_addr):
        pass

    def store(self):
        self.store_regs()

    def restore(self):
        self.restore_regs()

class QlLinuxThreadManagement(QlThreadManagement):
    def __init__(self, ql, time_slice = 1000, count_slice = 1000, bbl_slice = 300, mode = BBL_MODE, ):
        super(QlLinuxThreadManagement, self).__init__(ql)
        self.cur_thread = None
        self.running_thread_list = []
        self.ending_thread_list = []
        self.blocking_thread_list = []
        self.main_thread = None
        self.ql = ql

        self.mode = mode
        self.time_slice = time_slice
        self.count_slice = count_slice
        self.bbl_slice = bbl_slice

        if mode == TIME_MODE:
            self.thread_slice = time_slice
        elif mode == COUNT_MODE:
            self.thread_slice = count_slice
        elif mode == BBL_MODE:
            self.thread_slice = bbl_slice
            self.bbl_counter = 0
            self.bbl_count = 0
            self.setup_bbl_hook()
        else:
            raise

        self.runing_time = 0

    def run(self):
        if len(self.running_thread_list) == 0:
            self.ql.dprint(D_INFO, '[!] No executable thread!')
            return

        if self.main_thread not in self.running_thread_list:
            self.ql.dprint(D_INFO, '[!] No main thread!')
            return

        while True:
            running_thread_num = len(self.running_thread_list)
            blocking_thread_num = len(self.blocking_thread_list)
            if running_thread_num == 1 and blocking_thread_num == 0:
                thread_slice = 0
            else:
                thread_slice = self.thread_slice

            if running_thread_num != 0:
                for i in range(running_thread_num):
                    self.cur_thread = self.running_thread_list[i]
                    self.ql.dprint(D_INFO, "[+] Currently running pid is: %d; tid is: %d " % (
                    os.getpid(), self.cur_thread.get_thread_id()))
                    
                    if self.mode == TIME_MODE:
                        self.runing_time += self.cur_thread.run(time_slice = thread_slice, mode = TIME_MODE)
                    elif self.mode == COUNT_MODE:
                        self.runing_time += self.cur_thread.run(count_slice = thread_slice, mode = COUNT_MODE)
                    elif self.mode == BBL_MODE:
                        self.runing_time += self.cur_thread.run(bbl_slice = thread_slice, mode = BBL_MODE)
                    else:
                        raise

                    if self.cur_thread.is_running():
                        if self.cur_thread.stop_event == THREAD_EVENT_CREATE_THREAD:
                            new_pc = self.ql.arch.get_pc()
                            self.cur_thread.stop_return_val.set_start_address(new_pc)
                            self.add_running_thread(self.cur_thread.stop_return_val)
                            self.cur_thread.stop_return_val = None
                    elif self.cur_thread.is_blocking():
                        pass
                    else:
                        if self.cur_thread == self.main_thread:
                            self.exit_world()
                            return

                        if self.cur_thread.stop_event == THREAD_EVENT_EXIT_GROUP_EVENT:
                            self.exit_world()
                            return

                        elif self.cur_thread.stop_event == THREAD_EVENT_UNEXECPT_EVENT:
                            self.exit_world()
                            return

                        self.cur_thread = None
                        continue

                    self.cur_thread.suspend()
                    self.cur_thread = None
            else:
                if self.mode == TIME_MODE:
                    self.runing_time += thread_slice
                    time.sleep(thread_slice / 1000000)
                elif self.mode == COUNT_MODE:
                    self.runing_time += (thread_slice * 1)
                    time.sleep((thread_slice * 1) / 1000000)
                elif self.mode == BBL_MODE:
                    self.runing_time += (thread_slice * 3)
                    time.sleep((thread_slice * 1) / 1000000)
                else:
                    raise

            self.clean_running_thread()
            self.clean_blocking_thread()

    def setup_bbl_hook(self):
        def bbl_count_cb(ql, addr, size):
            if self.bbl_count == 0:
                return

            self.bbl_counter += 1

            if self.bbl_counter > self.bbl_count:
                ql.emu_stop()

        self.ql.hook_block(bbl_count_cb)

    def set_bbl_count(self, bbl_count):
        self.bbl_count = bbl_count
        self.clear_bbl_count()

    def clear_bbl_count(self):
        self.bbl_counter = 0

    def set_main_thread(self, mt):
        self.main_thread = mt
        self.add_running_thread(mt)

    def set_time_slice(self, t):
        self.time_slice = t
        if self.mode == TIME_MODE:
            self.thread_slice = t

    def set_count_slice(self, c):
        self.count_slice = c
        if self.mode == COUNT_MODE:
            self.thread_slice = c
    
    def set_bbl_slice(self, b):
        self.bbl_slice = b
        if self.mode == BBL_MODE:
            self.thread_slice = b

    def add_running_thread(self, t):
        if t not in self.running_thread_list:
            self.running_thread_list.append(t)

    def add_blocking_thread(self, t):
        if t not in self.blocking_thread_list:
            self.blocking_thread_list.append(t)

    def add_ending_thread(self, t):
        if t not in self.ending_thread_list:
            self.ending_thread_list.append(t)

    def clean_running_thread(self):
        tmp_list = self.running_thread_list
        self.running_thread_list = []
        for t in tmp_list:
            if t.is_running():
                self.add_running_thread(t)
            elif t.is_blocking():
                self.add_blocking_thread(t)
            else:
                self.add_ending_thread(t)

    def clean_blocking_thread(self):
        tmp_list = self.blocking_thread_list
        self.blocking_thread_list = []
        for t in tmp_list:
            if t.is_running():
                self.add_running_thread(t)
            elif t.is_continue_blocking():
                self.add_blocking_thread(t)
            else:
                self.add_running_thread(t)
                t.running()

    def exit_world(self):
        if self.ql.os.child_processes == True:
            os._exit(0)

        for t in self.running_thread_list:
            t.store()
            t.stop()
            self.add_ending_thread(t)
        for t in self.blocking_thread_list:
            t.store()
            t.stop()
            self.add_blocking_thread(t)
        self.running_thread_list = []
        self.blocking_thread_list = []

    def clean_world(self):
        self.running_thread_list = []
        self.blocking_thread_list = []
        self.ending_thread_list = []
