#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from ..utils import ql_setup_logging_file, ql_setup_logging_stream, ql_setup_logger
import os, time

THREAD_EVENT_INIT_VAL = 0
THREAD_EVENT_EXIT_EVENT = 1
THREAD_EVENT_UNEXECPT_EVENT = 2
THREAD_EVENT_EXECVE_EVENT = 3
THREAD_EVENT_CREATE_THREAD = 4
THREAD_EVENT_BLOCKING_EVENT = 5
THREAD_EVENT_EXIT_GROUP_EVENT = 6

THREAD_STATUS_RUNNING = 0
THREAD_STATUS_BLOCKING = 1
THREAD_STATUS_TERMINATED = 2
THREAD_STATUS_TIMEOUT = 3

#GLOBAL_THREAD_ID = 0

class Thread:
    def __init__(self, ql, thread_management = None, start_address = 0, context = None, total_time = 0, special_settings_arg = None, special_settings_fuc = None, set_child_tid_addr = None):
        #global GLOBAL_THREAD_ID
        if ql.global_thread_id == 0:
            ql.global_thread_id = os.getpid() + 1000

        self.total_time = total_time
        self.runing_time = 0
        self.context = context
        self.ql = ql
        self.special_settings_arg = special_settings_arg
        self.special_settings_fuc = special_settings_fuc
        self.until_addr = ql.until_addr
        self.start_address = start_address
        self.status = THREAD_STATUS_RUNNING
        self.stop_event = THREAD_EVENT_INIT_VAL
        self.stop_return_val = None
        self.return_val = 0
        self.blocking_condition_fuc = None
        self.blocking_condition_arg = None
        self.thread_id = ql.global_thread_id
        self.thread_management = None
        self.current_path = ql.current_path
        self.log_file_fd = None

        _logger = ql_setup_logger(str(self.thread_id)) if ql.log_split else ql_setup_logger()
        _logger = ql_setup_logging_stream(self.ql, _logger)

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

        ql.global_thread_id += 1
    
    def run(self, timeout = 0):
        # Set the time of the current run
        if timeout == 0 and self.total_time != 0:
            time_slice = self.total_time - self.runing_time
        else:
            time_slice = timeout
        
        # Initialize, stop event
        self.return_val = 0
        self.stop_event = THREAD_EVENT_INIT_VAL
        
        # Restore the context of the currently executing thread and set tls
        self.ql.uc.context_restore(self.context)
        if self.special_settings_fuc != None and self.special_settings_arg != None:
            self.special_settings_fuc(self.ql, self, self.special_settings_arg)
        
        # Run and log the run event
        s_time = int(time.time() * 1000000)
        self.start_address = self.ql.pc
        self.ql.uc.emu_start(self.start_address, self.until_addr, time_slice)
        e_time = int(time.time() * 1000000)
        
        self.runing_time += (e_time - s_time)
        
        if self.total_time != 0 and self.runing_time >= self.total_time:
            self.status = THREAD_STATUS_TIMEOUT
        
        if self.ql.archfunc.get_pc() == self.until_addr:
            self.stop()
            self.stop_event = THREAD_EVENT_EXIT_EVENT
        
        return (e_time - s_time)
    
    def suspend(self):
        self.context = self.ql.uc.context_save()
        self.start_address = self.ql.archfunc.get_pc()
    
    def save(self):
        self.context = self.ql.uc.context_save()
        self.start_address = self.ql.archfunc.get_pc()
    
    def set_start_address(self, addr):
        old_context = self.ql.uc.context_save()
        self.ql.uc.context_restore(self.context)
        self.ql.pc = addr
        self.save()
        self.ql.uc.context_restore(old_context)
    
    def set_special_settings_arg(self, addr):
        self.special_settings_arg = addr
    
    def set_special_settings_fuc(self, fuc):
        #For generalization here, I define it as a special setting function, which will be called after restoring the context. 
        #In x86 linux, it is used to set tls.
        self.special_settings_fuc = fuc
    
    def set_context(self, con):
        self.context = con
    
    def set_clear_child_tid_addr(self, addr):
        self.clear_child_tid_address = addr
    
    def _on_stop(self):
        if self.clear_child_tid_address != None:
            self.ql.mem.write(self.clear_child_tid_address, self.ql.pack32(0))

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
    
    def set_until_addr(self, until_addr):
        self.until_addr = until_addr
    
    def new_thread_id(self):
        #global GLOBAL_THREAD_ID
        self.thread_id = self.ql.global_thread_id
        self.ql.global_thread_id += 1
    
    def update_global_thread_id(self):
        #global GLOBAL_THREAD_ID
        self.ql.global_thread_id = os.getpid()
    
    def set_thread_log_file(self, log_dir):
        if self.ql.log_split and log_dir != None:
            _logger = self.ql.log_file_fd
            self.log_file_fd = ql_setup_logging_file(self.ql.output, log_dir, _logger)
    
    def get_current_path(self):
        return self.current_path
    
    def set_current_path(self, path):
        self.current_path = path
        

class ThreadManagement:
    def __init__(self, ql, time_slice = 1000):
        self.cur_thread = None
        self.running_thread_list = []
        self.ending_thread_list = []
        self.blocking_thread_list = []
        self.main_thread = None
        self.ql = ql
        self.time_slice = time_slice
        self.total_time = ql.timeout
        self.runing_time = 0

    def run(self):
        if len(self.running_thread_list) == 0:
            self.ql.dprint(0, '[!] No executable thread!')
            return
        
        if self.main_thread not in self.running_thread_list:
            self.ql.dprint(0, '[!] No main thread!')
            return
        
        while True:
            running_thread_num = len(self.running_thread_list)
            blocking_thread_num = len(self.blocking_thread_list)
            if running_thread_num == 1 and blocking_thread_num == 0:
                time_slice = 0
            else:
                time_slice = self.time_slice
            
            if running_thread_num != 0:
                for i in range(running_thread_num):
                    self.cur_thread = self.running_thread_list[i]
                    self.ql.dprint(0, "[+] Currently running pid is: %d; tid is: %d " % (
                    os.getpid(), self.cur_thread.get_thread_id()))
                    
                    self.runing_time += self.running_thread_list[i].run(time_slice)

                    if self.running_thread_list[i].is_running():
                        if self.running_thread_list[i].stop_event == THREAD_EVENT_CREATE_THREAD:
                            new_pc = self.ql.archfunc.get_pc()
                            self.cur_thread.stop_return_val.set_start_address(new_pc)
                            self.add_running_thread(self.cur_thread.stop_return_val)
                            self.cur_thread.stop_return_val = None
                    elif self.running_thread_list[i].is_blocking():
                        pass
                    else:
                        if self.cur_thread == self.main_thread:
                            self.exit_world()
                            return
                        
                        if self.running_thread_list[i].stop_event == THREAD_EVENT_EXIT_GROUP_EVENT:
                            self.exit_world()
                            return
                        elif self.running_thread_list[i].stop_event == THREAD_EVENT_UNEXECPT_EVENT:
                            self.exit_world()
                            return
                        self.cur_thread = None

                        continue

                    self.cur_thread = None
                    self.running_thread_list[i].suspend()
            else:
                self.runing_time += time_slice
                time.sleep(time_slice / 1000000)

            self.clean_running_thread()
            self.clean_blocking_thread()
    
    def set_main_thread(self, mt):
        self.main_thread = mt
        self.add_running_thread(mt)
    
    def set_time_slice(self, t):
        self.time_slice = t
    
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
            if t.is_continue_blocking():
                self.add_blocking_thread(t)
            else:
                self.add_running_thread(t)
                t.running()
    
    def exit_world(self):
        if self.ql.child_processes == True:
            os._exit(0)

        for t in self.running_thread_list:
            t.save()
            t.stop()
            self.add_ending_thread(t)
        for t in self.blocking_thread_list:
            t.save()
            t.stop()
            self.add_blocking_thread(t)
        self.running_thread_list = []
        self.blocking_thread_list = []
    
    def clean_world(self):
        self.running_thread_list = []
        self.blocking_thread_list = []
        self.ending_thread_list = []
