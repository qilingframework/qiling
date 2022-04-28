#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn import UcError
from unicorn.x86_const import UC_X86_INS_SYSCALL

from qiling import Qiling
from qiling.arch.x86_const import GS_SEGMENT_ADDR, GS_SEGMENT_SIZE
from qiling.arch.x86_utils import GDTManager, SegmentManager86, SegmentManager64
from qiling.arch import arm_utils
from qiling.cc import QlCC, intel, arm, mips, riscv, ppc
from qiling.const import QL_ARCH, QL_OS
from qiling.os.fcall import QlFunctionCall
from qiling.os.const import *
from qiling.os.posix.posix import QlOsPosix

from . import futex
from . import thread

class QlOsLinux(QlOsPosix):
    type = QL_OS.LINUX

    def __init__(self, ql: Qiling):
        super(QlOsLinux, self).__init__(ql)

        self.ql = ql

        cc: QlCC = {
            QL_ARCH.X86     : intel.cdecl,
            QL_ARCH.X8664   : intel.amd64,
            QL_ARCH.ARM     : arm.aarch32,
            QL_ARCH.ARM64   : arm.aarch64,
            QL_ARCH.MIPS    : mips.mipso32,
            QL_ARCH.RISCV   : riscv.riscv,
            QL_ARCH.RISCV64 : riscv.riscv,
            QL_ARCH.PPC     : ppc.ppc,
        }[ql.arch.type](ql.arch)

        self.fcall = QlFunctionCall(ql, cc)

        self.thread_class = None
        self.futexm = None
        self.fh = None
        self.function_after_load_list = []
        self.elf_mem_start = 0x0
        self.load()


    def load(self):
        self.futexm = futex.QlLinuxFutexManagement()

        # ARM
        if self.ql.arch.type == QL_ARCH.ARM:
            self.ql.arch.enable_vfp()
            self.ql.hook_intno(self.hook_syscall, 2)
            self.thread_class = thread.QlLinuxARMThread
            arm_utils.init_linux_traps(self.ql, {
                'memory_barrier': 0xffff0fa0,
                'cmpxchg': 0xffff0fc0,
                'get_tls': 0xffff0fe0
            })

        # MIPS32
        elif self.ql.arch.type == QL_ARCH.MIPS:
            self.ql.hook_intno(self.hook_syscall, 17)
            self.thread_class = thread.QlLinuxMIPS32Thread

        # ARM64
        elif self.ql.arch.type == QL_ARCH.ARM64:
            self.ql.arch.enable_vfp()
            self.ql.hook_intno(self.hook_syscall, 2)
            self.thread_class = thread.QlLinuxARM64Thread

        # X86
        elif self.ql.arch.type == QL_ARCH.X86:
            self.gdtm = GDTManager(self.ql)

            # setup gdt and segments selectors
            segm = SegmentManager86(self.ql.arch, self.gdtm)
            segm.setup_cs_ds_ss_es(0, 4 << 30)

            self.ql.hook_intno(self.hook_syscall, 0x80)
            self.thread_class = thread.QlLinuxX86Thread

        # X8664
        elif self.ql.arch.type == QL_ARCH.X8664:
            self.gdtm = GDTManager(self.ql)

            # setup gdt and segments selectors
            segm = SegmentManager64(self.ql.arch, self.gdtm)
            segm.setup_cs_ds_ss_es(0, 4 << 30)
            segm.setup_gs(GS_SEGMENT_ADDR, GS_SEGMENT_SIZE)

            self.ql.hook_insn(self.hook_syscall, UC_X86_INS_SYSCALL)
            # Keep test for _cc
            #self.ql.hook_insn(hook_posix_api, UC_X86_INS_SYSCALL)
            self.thread_class = thread.QlLinuxX8664Thread     

        elif self.ql.arch.type == QL_ARCH.RISCV:
            self.ql.arch.enable_float()
            self.ql.hook_intno(self.hook_syscall, 8)
            self.thread_class = None

        elif self.ql.arch.type == QL_ARCH.RISCV64:
            self.ql.arch.enable_float()
            self.ql.hook_intno(self.hook_syscall, 8)
            self.thread_class = None

        elif self.ql.arch.type == QL_ARCH.PPC:
            self.ql.arch.enable_float()
            self.ql.hook_intno(self.hook_syscall, 8)
            self.thread_class = None

        # on fork or execve, do not inherit opened files tagged as 'close on exec'
        for i in range(len(self.fd)):
            if getattr(self.fd[i], 'close_on_exec', 0):
                self.fd[i] = None

    def hook_syscall(self, ql, intno = None):
        return self.load_syscall()


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
                        if self.ql.arch.type == QL_ARCH.ARM and entry_address & 1 == 1:
                            entry_address -= 1
                        self.ql.emu_start(self.ql.loader.entry_point, entry_address, self.ql.timeout)
                        self.ql.do_lib_patch()
                        self.run_function_after_load()
                        self.ql.loader.skip_exit_check = False
                        self.ql.write_exit_trap()

                    self.ql.emu_start(self.ql.loader.elf_entry, self.exit_point, self.ql.timeout, self.ql.count)

        except UcError:
            self.emu_error()
            raise

        # display summary
        for entry in self.stats.summary():
            self.ql.log.debug(entry)
