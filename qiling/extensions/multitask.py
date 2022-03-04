# Ziqiao Kong (mio@lazym.io)

from typing import Dict
from unicorn import *
from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_RIP
from unicorn.arm64_const import UC_ARM64_REG_PC
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_CPSR
from unicorn.mips_const import UC_MIPS_REG_PC
from unicorn.m68k_const import UC_M68K_REG_PC
from unicorn.riscv_const import UC_RISCV_REG_PC
from unicorn.ppc_const import UC_PPC_REG_PC
from unicorn.sparc_const import UC_SPARC_REG_PC

import gevent
import gevent.threadpool
import gevent.lock
import threading

# This class is named UnicornTask be design since it's not a
# real thread. The expected usage is to inherit this class
# and overwrite specific methods.
class UnicornTask:

    def __init__(self, uc: Uc, begin: int, end: int, task_id = None):
        self._uc = uc
        self._begin = begin
        self._end = end
        self._stop_request = False
        self._ctx = None
        self._task_id = None

    @property
    def pc(self):
        arch = self._uc.ctl_get_arch()
        mode = self._uc.ctl_get_mode()

        # This extension is designed to be independent of Qiling, so let's
        # do this manually...
        if arch == UC_ARCH_X86:
            if (mode & UC_MODE_32) != 0:
                return self._uc.reg_read(UC_X86_REG_EIP)
            elif (mode & UC_MODE_64) != 0:
                return self._uc.reg_read(UC_X86_REG_RIP)
        elif arch == UC_ARCH_MIPS:
            return self._uc.reg_read(UC_MIPS_REG_PC)
        elif arch == UC_ARCH_ARM:
            pc = self._uc.reg_read(UC_ARM_REG_PC)
            if (self._uc.reg_read(UC_ARM_REG_CPSR) & (1 << 5)):
                return pc | 1
            else:
                return pc
        elif arch == UC_ARCH_ARM64:
            return self._uc.reg_read(UC_ARM64_REG_PC)
        elif arch == UC_ARCH_PPC:
            return self._uc.reg_read(UC_PPC_REG_PC)
        elif arch == UC_ARCH_M68K:
            return self._uc.reg_read(UC_M68K_REG_PC)
        elif arch == UC_ARCH_SPARC:
            return self._uc.reg_read(UC_SPARC_REG_PC)
        elif arch == UC_ARCH_RISCV:
            return self._uc.reg_read(UC_RISCV_REG_PC)
        
        # Really?
        return 0

    def save(self):
        """ This method is used to save the task context.
            Overwrite this method to implement specifc logic.
        """
        return self._uc.context_save()
    
    def restore(self, context):
        """ This method is used to restore the task context.
            Overwrite this method to implement specific logic.
        """
        self._uc.context_restore(context)
        self._begin = self.pc

    def _run(self):
        # This method is not intended to be overwritten!
        try:
            self._uc.emu_start(self._begin, self._end, 0, 0)
        except UcError as err:
            return err.errno
        
        return UC_ERR_OK

    def on_start(self):
        """ This callback is triggered when a task gets scheduled.
        """
        if self._ctx:
            self.restore(self._ctx)

    def on_interrupted(self, ucerr: int):
        """ This callback is triggered when a task gets interrupted, which
            is useful to emulate a clock interrupt.
        """
        self._ctx = self.save()

    def on_exit(self):
        """ This callback is triggered when a task is about to exit.
        """
        pass

# This is the core scheduler of a multi task unicorn.
# To implement a non-block syscall:
#    1. Record the syscall in the hook, but **do nothing**
#    2. Stop emulation.
#    3. Handle the syscall in the on_interruped callback with
#       proper **gevent functions** like gevent.sleep instead
#       of time.sleep.
#    4. In this case, gevent would schedule another task to
#       take emulation if the task is blocked.
#
# Bear in mind that only one task can be picked to emulate at
# the same time.
class MultiTaskUnicorn:

    def __init__(self, uc: Uc, interval: float = 0.5):
        # This takes over the ownershtip of uc instance
        self._uc = uc
        self._interval = interval
        self._tasks = {} # type: Dict[int, UnicornTask]
        self._task_id_counter = 2000
        self._to_stop = False
        self._cur_utk_id = None
        self._running = False
        self._run_lock = threading.RLock()

    @property
    def current_thread(self):
        return self._tasks[self._cur_utk_id]

    @property
    def running(self):
        return self._running
    
    def _next_task_id(self):
        while self._task_id_counter in self._tasks:
            self._task_id_counter += 1
        
        return self._task_id_counter

    def _utk_run(self, utk: UnicornTask):
        # Only one thread can start emulation at the same time, but
        # some other greenlets may do other async work.
        with self._run_lock:
            self._running = True
            result = utk._run()
            self._running = False
        return result

    def _task_main(self, utk_id: int):

        utk = self._tasks[utk_id]

        while True:
            # utk may be stopped before running once, check it.
            if utk._stop_request:
                break
            
            self._cur_utk_id = utk_id

            utk.on_start()

            with gevent.Timeout(self._interval, False):
                try:
                    pool = gevent.get_hub().threadpool # type: gevent.threadpool.ThreadPool
                    task = pool.spawn(self._utk_run, utk) # Run unicorn in a separate thread.
                    task.wait()
                finally:
                    if not task.done():
                        # Interrupted by timeout, in this case we call uc_emu_stop.
                        self._uc.emu_stop()
                    
                    # Wait until we get the result.
                    ucerr = task.get()

            if utk._stop_request:
                utk.on_exit()
                break
            else:
                utk.on_interrupted(ucerr)

            if self._to_stop:
                break
            
            # on_interrupted callback may have asked us to stop.
            if utk._stop_request:
                break

            # Give up control at once.
            gevent.sleep(0)

        del self._tasks[utk_id]

    def save(self):
        return { k: v.save() for k, v in self._tasks.items() }

    def restore(self, threads_context: dict):
        for task_id, context in threads_context:
            if task_id in self._tasks:
                self._tasks[task_id].restore(context)

    def task_create(self, utk: UnicornTask):
        """ Create a unicorn task. utk should be a initialized UnicornTask object.
            If the task_id is not set, we generate one.

            utk: The task to add.
        """
        if not isinstance(utk, UnicornTask):
            raise TypeError("Expect a UnicornTask or derived class")
        if utk._task_id is None:
            utk._task_id = self._next_task_id()
        self._tasks[utk._task_id] = utk
        return utk._task_id

    def task_exit(self, utk_id):
        """ Stop a task.
            
            utk_id: The id returned from task_create.
        """
        if utk_id not in self._tasks:
            return
        
        if utk_id == self._cur_utk_id and self._running:
            self._uc.emu_stop()
        
        self._tasks[utk_id]._stop_request = True

    def emu_once(self, begin: int, end: int, timeout: int, count: int):
        """ Emulate an area of code just once. This is equivalent to uc_emu_start but is gevent-aware.
            NOTE: Calling this method may cause current greenlet to be switched out.

            begin, end, timeout, count: refer to uc_emu_start
        """
        def _once(begin: int, end: int, timeout: int, count: int):
            with self._run_lock:
                try:
                    self._uc.emu_start(begin, end, timeout, count)
                except UcError as err:
                    return err.errno
            
            return UC_ERR_OK

        pool = gevent.get_hub().threadpool # type: gevent.threadpool.ThreadPool
        task = pool.spawn(_once, begin, end, timeout, count)
        return task.get()

    def stop(self):
        """ This will stop all running tasks.
        """
        self._to_stop = True
        if self._running:
            self._uc.emu_stop()

    def start(self):
        """ This will start emulation until all tasks get done.
        """
        workset = {} # type: Dict[int, gevent.Greenlet]
        self._to_stop = False

        while len(self._tasks) != 0:
            
            new_workset = { k: v for k, v in workset.items() if not v.dead}

            for utk_id in self._tasks:
                new_workset[utk_id] = gevent.spawn(self._task_main, utk_id)

            workset = new_workset

            gevent.joinall(list(workset.values()), raise_error=True)