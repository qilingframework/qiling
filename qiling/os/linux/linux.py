#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

from qiling.const import *
from qiling.arch.x86 import *

from qiling.os.posix.posix import QlOsPosix
from .const import *
from .utils import *
from .futex import *
from .thread import *

class QlOsLinux(QlOsPosix):
    def __init__(self, ql):
        super(QlOsLinux, self).__init__(ql)
        self.ql = ql
        self.thread_class = None
        self.futexm = None
        self.function_hook_tmp = []
        self.fh = None
        self.function_after_load_list = []
        self.load()

    def load(self):
        self.futexm = QlLinuxFutexManagement()

        # ARM
        if self.ql.archtype== QL_ARCH.ARM:
            self.ql.arch.enable_vfp()
            self.ql.hook_intno(self.hook_syscall, 2)
            self.thread_class = QlLinuxARMThread
            ql_arm_init_get_tls(self.ql)


        # MIPS32
        elif self.ql.archtype== QL_ARCH.MIPS:      
            self.ql.hook_intno(self.hook_syscall, 17)
            self.thread_class = QlLinuxMIPS32Thread

        # ARM64
        elif self.ql.archtype== QL_ARCH.ARM64:
            self.ql.arch.enable_vfp()
            self.ql.hook_intno(self.hook_syscall, 2)
            self.thread_class = QlLinuxARM64Thread

        # X86
        elif  self.ql.archtype== QL_ARCH.X86:
            self.gdtm = GDTManager(self.ql)
            ql_x86_register_cs(self)
            ql_x86_register_ds_ss_es(self)
            self.ql.hook_intno(self.hook_syscall, 0x80)
            self.thread_class = QlLinuxX86Thread

        # X8664
        elif  self.ql.archtype== QL_ARCH.X8664:
            self.gdtm = GDTManager(self.ql)
            ql_x86_register_cs(self)
            ql_x86_register_ds_ss_es(self)
            self.ql.hook_insn(self.hook_syscall, UC_X86_INS_SYSCALL)
            self.thread_class = QlLinuxX8664Thread
       
    def hook_syscall(self, int= None, intno= None):
        return self.load_syscall(intno)

    def add_function_hook(self, fn, cb, userdata = None):
        self.function_hook_tmp.append((fn, cb, userdata))
    
    def register_function_after_load(self, function):
        if function not in self.function_after_load_list:
            self.function_after_load_list.append(function)

    def run_function_after_load(self):
        for f in self.function_after_load_list:
            f()

    def run(self):
        for function, callback, userdata in self.ql.os.function_hook_tmp:
            self.ql.os.function_hook.add_function_hook(function, callback, userdata)

        if self.ql.exit_point is not None:
            self.exit_point = self.ql.exit_point

        try:
            if self.ql.shellcoder:
                self.ql.emu_start(self.entry_point, (self.entry_point + len(self.ql.shellcoder)), self.ql.timeout, self.ql.count)
            else:
                if self.ql.multithread == True:
                    # start multithreading
                    thread_management = QlLinuxThreadManagement(self.ql)
                    self.ql.os.thread_management = thread_management
                    main_thread = self.thread_class(self.ql, thread_management, total_time = self.ql.timeout)
                    main_thread.store_regs()
                    main_thread.set_start_address(self.ql.loader.entry_point)
                    thread_management.set_main_thread(main_thread)

                    # enable lib patch
                    if self.ql.loader.elf_entry != self.ql.loader.entry_point:
                        main_thread.set_exit_point(self.ql.loader.elf_entry)
                        thread_management.run()
                        self.ql.enable_lib_patch()
                        self.run_function_after_load()

                        main_thread.set_start_address(self.ql.loader.elf_entry)
                        main_thread.set_exit_point(self.exit_point)
                        main_thread.running()

                        thread_management.clean_world()
                        thread_management.set_main_thread(main_thread)

                    thread_management.run()
                else:
                    if self.ql.loader.elf_entry != self.ql.loader.entry_point:
                        self.ql.emu_start(self.ql.loader.entry_point, self.ql.loader.elf_entry, self.ql.timeout)
                        self.ql.enable_lib_patch()
                        self.run_function_after_load()
                    
                    if  self.ql.entry_point is not None:
                        self.ql.loader.elf_entry = self.ql.entry_point
                    
                    self.ql.emu_start(self.ql.loader.elf_entry, self.exit_point, self.ql.timeout, self.ql.count)

        except:
            self.emu_error()
            raise

        if self.ql.internal_exception != None:
            raise self.ql.internal_exception
