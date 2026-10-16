#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import math
from enum import Enum
from typing import TYPE_CHECKING, cast, Optional

from qiling import Qiling
from qiling.const import QL_ARCH, QL_HOOK_BLOCK
from qiling.os.thread import QlThread
from qiling.loader.pe import QlLoaderPE

if TYPE_CHECKING:
    from qiling.os.windows.windows import QlOsWindows

class THREAD_STATUS(Enum):
    READY = 0
    RUNNING = 1
    TERMINATED = 2

class QlWindowsThread(QlThread):
    # static var
    ID = 0

    def __init__(self, ql: Qiling, status: THREAD_STATUS = THREAD_STATUS.RUNNING):
        super().__init__(ql)

        self.ql = ql
        self.id =  QlWindowsThread.ID
        QlWindowsThread.ID += 1
        self.status = status
        self.waitforthreads = []
        self.tls_vector_addr = 0
        self.tls_initialized_indices = set()

    # create a new thread with context
    @classmethod
    def create(cls, ql: Qiling, stack_size: int, func_addr: int, func_params: int, status: THREAD_STATUS) -> 'QlWindowsThread':
        os = cast('QlOsWindows', ql.os)

        thread = cls(ql, status)

        PAGE_SIZE = 4096

        # According to Microsoft documentation:
        # "The system rounds this value to the nearest page.
        # If this parameter is zero, the new thread uses the default size for the executable."
        # https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
        stack_size = int(math.ceil(max(stack_size, 1) / PAGE_SIZE)) * PAGE_SIZE

        # create new stack
        new_stack = os.heap.alloc(stack_size) + stack_size

        asize = ql.arch.pointersize
        context = ql.arch.regs.save()

        # set return address
        ql.mem.write_ptr(new_stack - asize, os.thread_manager.thread_ret_addr)

        # set parameters
        if ql.arch.type == QL_ARCH.X86:
            ql.mem.write_ptr(new_stack, func_params)
        elif ql.arch.type == QL_ARCH.X8664:
            context["rcx"] = func_params

        # set eip/rip, ebp/rbp, esp/rsp
        if ql.arch.type == QL_ARCH.X86:
            context["eip"] = func_addr
            context["ebp"] = new_stack - asize
            context["esp"] = new_stack - asize

        elif ql.arch.type == QL_ARCH.X8664:
            context["rip"] = func_addr
            context["rbp"] = new_stack - asize
            context["rsp"] = new_stack - asize

        thread.saved_context = context

        loader = cast('QlLoaderPE', ql.loader)
        thread.init_tls(loader.tls_templates)

        return thread

    def suspend(self) -> None:
        self.saved_context = self.ql.arch.regs.save()

    def resume(self) -> None:
        self.ql.arch.regs.restore(self.saved_context)
        self.status = THREAD_STATUS.RUNNING

    def stop(self) -> None:
        self.status = THREAD_STATUS.TERMINATED

    def is_stop(self) -> bool:
        return self.status == THREAD_STATUS.TERMINATED

    def waitfor(self, thread: 'QlWindowsThread') -> None:
        self.waitforthreads.append(thread)

    def has_waitfor(self) -> bool:
        return any(not thread.is_stop() for thread in self.waitforthreads)

    def init_tls(self, tls_templates: list[bytes]):
        """Initialize or reinitialize TLS storage for the thread.

        If the thread has a TLS slot which was previously initialized
        in a prior call to `init_tls`, this TLS slot is skipped.

        Parameters:
            - `tls_templates` - Array of per-module or allocated TLS blocks.
            This array is cloned and used to initialize the thread's TLS vector.
        """
        
        # According to Microsoft documentation, the TLS vector has 
        # a minimum of 64 entries, but can be reallocated if more
        # entries are needed.
        # 
        # In practice most processes will only use a handful of entries,
        # so for simplicity we will assume that the process will not
        # need more than 64.
        TLS_VECTOR_ENTRIES = 64
        TLS_ADDRESS_MIN = 0x800000
        TLS_VECTOR_SIZE = TLS_VECTOR_ENTRIES * self.ql.arch.pointersize 

        if not self.tls_vector_addr:
            self.tls_vector_addr = self.ql.mem.map_anywhere(TLS_VECTOR_SIZE, TLS_ADDRESS_MIN)

            self.ql.log.debug(f'Init TLS for thread ID={self.id}')
            self.ql.log.debug(f'TLS vector at {self.tls_vector_addr:#x}')
        else:
            self.ql.log.debug(f'Reinit TLS for thread ID={self.id}')

        for module_tls_index, template in enumerate(tls_templates):
            if module_tls_index in self.tls_initialized_indices:
                self.ql.log.debug(f'Skipping TLS for module index={module_tls_index}; already initialized')
                continue

            if len(template) > 0:
                tls_block_addr = self.ql.mem.map_anywhere(len(template), TLS_ADDRESS_MIN)

                self.ql.log.debug(f'Module TLS index={module_tls_index}')
                
                self.ql.mem.write(tls_block_addr, template)

                self.ql.log.debug(f'Wrote TLS block at {self.tls_vector_addr:#x} ({len(template)} bytes)')

                # Write the pointer to the new TLS block to the thread's TLS vector
                self.ql.mem.write_ptr(self.tls_vector_addr + module_tls_index * self.ql.arch.pointersize, tls_block_addr)

            else:
                # If the template size is zero then this may be a TLS slot
                # allocated with e.g. TlsAlloc.
                self.ql.log.debug(f'Empty TLS index={module_tls_index}')

                # Zero-initialize the slot
                self.ql.mem.write_ptr(self.tls_vector_addr + module_tls_index * self.ql.arch.pointersize, 0)

            self.tls_initialized_indices.add(module_tls_index)

    def update_tls_address(self):
        """Update the `TlsAddress` pointer in the TEB to point
        to the given thread's TLS.

        This method must be called before a thread resumes execution.
        """
        loader = self.ql.loader

        if TYPE_CHECKING:
            loader = cast('QlLoaderPE', loader)
            
        loader.TEB.TlsAddress = self.tls_vector_addr

        self.ql.log.debug(f"Set TEB.TlsAddress={self.tls_vector_addr:#x} for thread ID {self.id}")


# Simple Thread Manager
class QlWindowsThreadManagement:
    TIME_SLICE = 10

    def __init__(self, ql: Qiling, os: 'QlOsWindows', cur_thread: QlWindowsThread):
        self.ql = ql

        # main thread
        self.cur_thread = cur_thread
        self.threads = [self.cur_thread]
        self.icount = 0
        self.thread_ret_addr = os.heap.alloc(8)

        # Index of the past-the-end TLS slot
        self.tls_index = 0
        self.tls_allocated_indices = set()

        # write nop to thread_ret_addr
        ql.mem.write(self.thread_ret_addr, b'\x90' * 8)

        def __thread_scheduler(ql: Qiling, address: int, size: int):
            if ql.arch.regs.arch_pc == self.thread_ret_addr:
                self.cur_thread.stop()
            else:
                self.icount += 1

            switched = self.do_schedule()

            # in case another thread was resumed, all remaining hooks should be skipped to prevent them
            # from running with the new thread's context.

            return QL_HOOK_BLOCK if switched else 0

        ql.hook_code(__thread_scheduler)

    def append(self, thread: QlWindowsThread):
        self.threads.append(thread)

    def do_schedule(self) -> bool:
        need_schedule = self.cur_thread.is_stop() or (self.icount % QlWindowsThreadManagement.TIME_SLICE) == 0
        switched = False

        if need_schedule:
            # if there is less than one thread, this loop won't run
            for i in range(1, len(self.threads)):
                next_id = (self.cur_thread.id + i) % len(self.threads)
                next_thread = self.threads[next_id]

                # find next thread
                if next_thread.status == THREAD_STATUS.RUNNING and not next_thread.has_waitfor():
                    if not self.cur_thread.is_stop():
                        self.cur_thread.suspend()

                    next_thread.resume()
                    next_thread.update_tls_address()
                    self.cur_thread = next_thread

                    switched = True
                    break

        return switched

    def init_tls(self, tls_templates: list[bytes]):
        """Initialize or reinitialize TLS storage for all currently
        running threads.

        This method should be called every time a new TLS template
        is added by the loader, in order to update TLS vectors for
        running threads.

        Parameters:
            - `tls_templates` - Array of per-module or manually
            allocated TLS blocks. This array is cloned and used
            to initialize each thread's TLS vector.
        """
        self.tls_index = len(tls_templates) - 1

        for thread in self.threads:
            thread.init_tls(tls_templates)

    def tls_alloc(self) -> int:
        """Allocate a TLS slot.

        Returns the index of the new TLS slot.
        """
        loader = cast('QlLoaderPE', self.ql.loader)

        current_tls_index = len(loader.tls_templates)
        self.tls_allocated_indices.add(current_tls_index)

        loader.tls_templates.append(bytes())

        self.init_tls(loader.tls_templates)

        return current_tls_index

    def tls_free(self, tls_index: int) -> bool:
        """Free a TLS slot that was previously allocated.

        Returns `True` if the TLS slot was successfully
        freed, `False` if the slot was not freed.

        Parameters:
            - `tls_index` - Index of the TLS slot to be freed.
        """
        if tls_index not in self.tls_allocated_indices:
            return False

        self.tls_allocated_indices.remove(tls_index)

        return True

    def tls_get_value(self, idx: int) -> Optional[int]:
        if idx not in self.tls_allocated_indices:
            return None
        
        return self.ql.mem.read_ptr(self.cur_thread.tls_vector_addr + idx * self.ql.arch.pointersize)

    def tls_set_value(self, idx: int, value: int) -> bool:
        if idx not in self.tls_allocated_indices:
            return False
        
        self.ql.mem.write_ptr(self.cur_thread.tls_vector_addr + idx * self.ql.arch.pointersize, value)

        return True

    def update_tls_address(self):
        """Update the `TlsAddress` pointer in the TEB to point
        to the currently running thread's TLS.

        This method must be called before a thread resumes execution.
        """
        if self.cur_thread is not None:
            self.cur_thread.update_tls_address()