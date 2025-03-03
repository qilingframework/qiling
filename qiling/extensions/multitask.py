# Lazymio (mio@lazym.io)

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

from typing import Dict, List, Optional


# This class is named UnicornTask be design since it's not a
# real thread. The expected usage is to inherit this class
# and overwrite specific methods.
#
# This class is a friend class of MultiTaskUnicorn
class UnicornTask:

    def __init__(self, uc: Uc, begin: int, end: int, task_id=None):
        self._uc = uc
        self._begin = begin
        self._end = end
        self._stop_request = False
        self._ctx = None
        self._task_id = None
        self._arch = self._uc._arch
        self._mode = self._uc._mode

    @property
    def pc(self) -> int:
        """ Get current PC of the thread. This property should only be accessed when
            the task is running.
        """
        raw_pc = self._raw_pc()

        if self._arch == UC_ARCH_ARM:
            return raw_pc | ((self._uc.reg_read(UC_ARM_REG_CPSR) >> 5) & 0b1)

        return raw_pc

    def _raw_pc(self) -> int:
        # This extension is designed to be independent of Qiling, so let's
        # do this manually...

        pc_reg = 0  # invalid reg

        if self._arch == UC_ARCH_X86:
            if self._mode & UC_MODE_32:
                pc_reg = UC_X86_REG_EIP
            elif self._mode & UC_MODE_64:
                pc_reg = UC_X86_REG_RIP

        elif self._arch == UC_ARCH_MIPS:
            pc_reg = UC_MIPS_REG_PC

        elif self._arch == UC_ARCH_ARM:
            pc_reg = UC_ARM_REG_PC

        elif self._arch == UC_ARCH_ARM64:
            pc_reg = UC_ARM64_REG_PC

        elif self._arch == UC_ARCH_PPC:
            pc_reg = UC_PPC_REG_PC

        elif self._arch == UC_ARCH_M68K:
            pc_reg = UC_M68K_REG_PC

        elif self._arch == UC_ARCH_SPARC:
            pc_reg = UC_SPARC_REG_PC

        elif self._arch == UC_ARCH_RISCV:
            pc_reg = UC_RISCV_REG_PC

        return self._uc.reg_read(pc_reg) if pc_reg else 0

    def _reach_end(self):
        # We may stop due to the scheduler asks us to, so check it manually.
        # print(f"{hex(self._raw_pc())} {hex(self._end)}")
        return self._raw_pc() == self._end

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


# This manages nested uc_emu_start calls and is designed as a friend
# class of MultiTaskUnicorn.
class NestedCounter:

    def __init__(self, mtuc: "MultiTaskUnicorn"):
        self._mtuc = mtuc

    def __enter__(self, *args, **kwargs):
        self._mtuc._nested_started += 1
        return self

    def __exit__(self, *args, **kwargs):
        self._mtuc._nested_started -= 1


# This mimic a Unicorn object by maintaining the same interface.
# If no task is registered, the behavior is exactly the same as
# a normal unicorn.
#
# Note: To implement a non-block syscall:
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
class MultiTaskUnicorn(Uc):

    def __init__(self, arch: int, mode: int, cpu: Optional[int], interval: Optional[int] = 100):
        """ Create a MultiTaskUnicorn object.
            Interval: Sceduling interval in **ms**. The longger interval, the better
            performance but less interrupts.
        """
        super().__init__(arch, mode)

        if cpu is not None:
            self.ctl_set_cpu_model(cpu)

        self._interval = interval
        self._tasks = {}  # type: Dict[int, UnicornTask]
        self._task_id_counter = 2000
        self._to_stop = False
        self._cur_utk_id = None
        self._running = False
        self._run_lock = threading.RLock()
        self._multitask_enabled = False
        self._count = 0
        self._nested_started = 0

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

    def _emu_start_locked(self, begin: int, end: int, timeout: int, count: int):
        with self._run_lock:
            try:
                self._running = True
                super().emu_start(begin, end, timeout, count)
                self._running = False
            except UcError as err:
                return err.errno

        return UC_ERR_OK

    def _emu_start_utk_locked(self, utk: UnicornTask):
        return self._emu_start_locked(utk._begin, utk._end, 0, 0)

    def _timeout_main(self, timeout: int):

        gevent.sleep(timeout / 1000)

        self.tasks_stop()

    def _task_main(self, utk_id: int):

        utk = self._tasks[utk_id]
        use_count = (self._count > 0)

        while True:
            # utk may be stopped before running once, check it.
            if utk._stop_request:
                return # If we have to stop due to a tasks_stop, we preserve all threads so that we may resume.

            self._cur_utk_id = utk_id

            utk.on_start()

            with gevent.Timeout(self._interval / 1000, False):
                try:
                    pool = gevent.get_hub().threadpool # type: gevent.threadpool.ThreadPool
                    task = pool.spawn(self._emu_start_utk_locked, utk) # Run unicorn in a separate thread.
                    task.wait()
                finally:
                    if not task.done():
                        # Interrupted by timeout, in this case we call uc_emu_stop.
                        super().emu_stop()

                    # Wait until we get the result.
                    ucerr = task.get()

            if utk._reach_end():
                utk._stop_request = True

            if use_count:
                self._count -= 1

                if self._count <= 0:
                    self.tasks_stop()
                    return

            if utk._stop_request:
                utk.on_exit()
                break
            else:
                utk.on_interrupted(ucerr)

            if self._to_stop:
                return

            # on_interrupted callback may have asked us to stop.
            if utk._stop_request:
                utk.on_exit()
                break

            # Give up control at once.
            gevent.sleep(0)

        del self._tasks[utk_id]

    def tasks_save(self):
        """ Save all tasks' contexts.
        """
        return { k: v.save() for k, v in self._tasks.items() }

    def tasks_restore(self, tasks_context: dict):
        """ Restore the contexts of all tasks.
        """
        for task_id, context in tasks_context:
            if task_id in self._tasks:
                self._tasks[task_id].restore(context)

    def task_create(self, utk: UnicornTask):
        """ Create a unicorn task. utk should be a initialized UnicornTask object.
            If the task_id is not set, we generate one.
            utk: The task to add.
        """
        if not isinstance(utk, UnicornTask):
            raise TypeError("Expect a UnicornTask or derived class")
        self._multitask_enabled = True
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
            self.emu_stop()

        self._tasks[utk_id]._stop_request = True

    def emu_start(self, begin: int, end: int, timeout: int, count: int):
        """ Emulate an area of code just once. This overwrites the original emu_start interface and
            provides extra cares when multitask is enabled. If no task is registerd, this call bahaves
            like the original emu_start.
            NOTE: Calling this method may cause current greenlet to be switched out.
            begin, end, timeout, count: refer to Uc.emu_start
        """
        if self._multitask_enabled:
            if self._nested_started > 0:
                with NestedCounter(self):
                    pool = gevent.get_hub().threadpool # type: gevent.threadpool.ThreadPool
                    task = pool.spawn(self._emu_start_locked, begin, end, timeout, count)
                    ucerr = task.get()

                    if ucerr != UC_ERR_OK:
                        raise UcError(ucerr)

                    return ucerr
            else:

                # Assume users resume on the last thread (and that should be the case)
                if self._cur_utk_id in self._tasks:
                    self._tasks[self._cur_utk_id]._begin = begin
                    self._tasks[self._cur_utk_id]._end = end
                else:
                    print(f"Warning: Can't found last thread we scheduled")

                # This translation is not accurate, though.
                self.tasks_start(count, timeout)
        else:
            return super().emu_start(begin, end, timeout, count)

    def emu_stop(self):
        """ Stop the emulation. If no task is registerd, this call bahaves like the original emu_stop.
        """
        if self._multitask_enabled:
            if self._running:
                super().emu_stop()
            # Stop the world as original uc_emu_stop does
            if self._nested_started == 1:
                self.tasks_stop()
        else:
            super().emu_stop()

    def tasks_stop(self):
        """ This will stop all running tasks. If no task is registered, this call does nothing.
        """
        if self._multitask_enabled:
            self._to_stop = True
            if self._running:
                super().emu_stop()

    def tasks_start(self, count: int = 0, timeout: int = 0):
        """ This will start emulation until all tasks get done.
            count: Stop after sceduling *count* times. <=0 disables this check.
            timeout: Stop after *timeout* ms. <=0 disables this check.
        """
        workset = [] # type: List[gevent.Greenlet]
        self._to_stop = False
        self._count = count

        if self._nested_started != 0:
            print("Warning: tasks_start is called inside an uc_emu_start!")
            return

        with NestedCounter(self):

            if self._count <= 0:
                self._count = 0

            if self._multitask_enabled:

                if timeout > 0:
                    workset.append(gevent.spawn(self._timeout_main, timeout))

                while len(self._tasks) != 0 and not self._to_stop:

                    new_workset = [ v for v in workset if not v.dead]

                    for utk_id in self._tasks:
                        new_workset.append(gevent.spawn(self._task_main, utk_id))

                    workset = new_workset

                    gevent.joinall(workset, raise_error=True)

                if len(self._tasks) == 0:
                    self._multitask_enabled = False
