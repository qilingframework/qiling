#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Callable
from unicorn import UcError

from qiling import Qiling
from qiling.arch.x86_const import UC_X86_INS_SYSCALL
from qiling.arch.x86 import GDTManager, ql_x8664_set_gs, ql_x86_register_cs, ql_x86_register_ds_ss_es
from qiling.cc import QlCC, intel, arm, mips
from qiling.const import QL_ARCH, QL_INTERCEPT
from qiling.os.fcall import QlFunctionCall
from qiling.os.const import *
from qiling.os.posix.const import NR_OPEN
from qiling.os.posix.posix import QlOsPosix

from . import utils
from . import futex
from . import thread

class QlOsLinux(QlOsPosix):
    def __init__(self, ql: Qiling):
        super(QlOsLinux, self).__init__(ql)

        self.ql = ql

        cc: QlCC = {
            QL_ARCH.X86   : intel.cdecl,
            QL_ARCH.X8664 : intel.amd64,
            QL_ARCH.ARM   : arm.aarch32,
            QL_ARCH.ARM64 : arm.aarch64,
            QL_ARCH.MIPS  : mips.mipso32
        }[ql.archtype](ql)

        self.fcall = QlFunctionCall(ql, cc)

        self.thread_class = None
        self.futexm = None
        self.fh = None
        self.function_after_load_list = []
        self.elf_mem_start = 0x0
        self.load()

        if self.ql.archtype == QL_ARCH.X8664:
            ql_x8664_set_gs(self.ql)

    def load(self):
        self.futexm = futex.QlLinuxFutexManagement()

        # ARM
        if self.ql.archtype == QL_ARCH.ARM:
            self.ql.arch.enable_vfp()
            self.ql.hook_intno(self.hook_syscall, 2)
            self.thread_class = thread.QlLinuxARMThread
            utils.ql_arm_init_get_tls(self.ql)

        # MIPS32
        elif self.ql.archtype == QL_ARCH.MIPS:
            self.ql.hook_intno(self.hook_syscall, 17)
            self.thread_class = thread.QlLinuxMIPS32Thread

        # ARM64
        elif self.ql.archtype == QL_ARCH.ARM64:
            self.ql.arch.enable_vfp()
            self.ql.hook_intno(self.hook_syscall, 2)
            self.thread_class = thread.QlLinuxARM64Thread

        # X86
        elif self.ql.archtype == QL_ARCH.X86:
            self.gdtm = GDTManager(self.ql)
            ql_x86_register_cs(self)
            ql_x86_register_ds_ss_es(self)
            self.ql.hook_intno(self.hook_syscall, 0x80)
            self.thread_class = thread.QlLinuxX86Thread

        # X8664
        elif self.ql.archtype == QL_ARCH.X8664:
            self.gdtm = GDTManager(self.ql)
            ql_x86_register_cs(self)
            ql_x86_register_ds_ss_es(self)
            self.ql.hook_insn(self.hook_syscall, UC_X86_INS_SYSCALL)
            # Keep test for _cc
            #self.ql.hook_insn(hook_posix_api, UC_X86_INS_SYSCALL)
            self.thread_class = thread.QlLinuxX8664Thread     
        
        for i in range(NR_OPEN):
            if hasattr(self.fd[i], 'close_on_exec') and \
                    self.fd[i].close_on_exec:
                self.fd[i] = 0

    def hook_syscall(self, int= None, intno= None):
        return self.load_syscall()


    def add_function_hook(self, fn: str, cb: Callable, intercept: QL_INTERCEPT):
        self.ql.os.function_hook.add_function_hook(fn, cb, intercept)


    def register_function_after_load(self, function):
        if function not in self.function_after_load_list:
            self.function_after_load_list.append(function)


    def run_function_after_load(self):
        for f in self.function_after_load_list:
            f()


    def run(self):
        if self.ql.exit_point is not None:
            self.exit_point = self.ql.exit_point

        try:
            if self.ql.code:
                self.ql.emu_start(self.entry_point, (self.entry_point + len(self.ql.code)), self.ql.timeout, self.ql.count)
            else:
                if self.ql.multithread == True:
                    # start multithreading
                    thread_management = thread.QlLinuxThreadManagement(self.ql)
                    self.ql.os.thread_management = thread_management
                    thread_management.run()

                else:
                    if  self.ql.entry_point is not None:
                        self.ql.loader.elf_entry = self.ql.entry_point

                    elif self.ql.loader.elf_entry != self.ql.loader.entry_point:
                        entry_address = self.ql.loader.elf_entry
                        if self.ql.archtype == QL_ARCH.ARM and entry_address & 1 == 1:
                            entry_address -= 1
                        self.ql.emu_start(self.ql.loader.entry_point, entry_address, self.ql.timeout)
                        self.ql.enable_lib_patch()
                        self.run_function_after_load()
                        self.ql.loader.skip_exit_check = False
                        self.ql.write_exit_trap()

                    self.ql.emu_start(self.ql.loader.elf_entry, self.exit_point, self.ql.timeout, self.ql.count)

        except UcError:
            # TODO: this is bad We need a better approach for this
            #if self.ql.output != QL_OUTPUT.DEBUG:
            #    return

            self.emu_error()
            raise
