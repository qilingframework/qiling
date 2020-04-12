#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

from unicorn import *

from unicorn.arm_const import *
from unicorn.x86_const import *
from unicorn.arm64_const import *
from unicorn.mips_const import *

from qiling.const import *


from qiling.arch.x86 import *

from qiling.os.utils import *
from qiling.os.posix.posix import QlOsPosix
from qiling.os.linux.const import *
from qiling.os.linux.utils import *
from qiling.os.linux.futex import *

class QlOsLinux(QlOsPosix):
    def __init__(self, ql):
        super(QlOsLinux, self).__init__(ql)
        self.ql = ql
        self.QL_LINUX_PREDEFINE_STACKSIZE = 0x21000
        self.QL_ARM_KERNEL_GET_TLS_ADDR = 0xFFFF0FE0
        self.thread_class = None
        self.futexm = None
        self.load()

    def load(self):
        """
        initiate UC needs to be in loader,
        or else it will kill execve
        """
        self.ql.uc = self.ql.arch.init_uc
        self.futexm = QlLinuxFutexManagement()

        # ARM
        if self.ql.archtype== QL_ARM:
            self.QL_LINUX_PREDEFINE_STACKADDRESS = 0xfff0d000
            self.ql.arch.enable_vfp()
            ql_arm_init_kernel_get_tls(self.ql)
            self.ql.hook_intr(self.hook_syscall)
            self.thread_class = QlLinuxARMThread

        # MIPS32
        elif self.ql.archtype== QL_MIPS32:
            self.QL_LINUX_PREDEFINE_STACKADDRESS = 0x7ff0d000
            self.QL_LINUX_PREDEFINE_STACKSIZE = 0x30000
            self.ql.hook_intr(self.hook_syscall)
            self.thread_class = QlLinuxMIPS32Thread

        # ARM64
        elif self.ql.archtype== QL_ARM64:
            self.QL_LINUX_PREDEFINE_STACKADDRESS = 0x7ffffffde000
            self.ql.arch.enable_vfp()
            self.ql.hook_intr(self.hook_syscall)
            self.thread_class = QlLinuxARM64Thread

        # X86
        elif  self.ql.archtype== QL_X86:
            self.QL_LINUX_PREDEFINE_STACKADDRESS = 0xfffdd000
            self.gdtm = GDTManager(self.ql)
            ql_x86_register_cs(self)
            ql_x86_register_ds_ss_es(self)
            self.ql.hook_intr(self.hook_syscall)
            self.thread_class = QlLinuxX86Thread

        # X8664
        elif  self.ql.archtype== QL_X8664:
            self.QL_LINUX_PREDEFINE_STACKADDRESS = 0x7ffffffde000
            self.gdtm = GDTManager(self.ql)
            ql_x86_register_cs(self)
            ql_x86_register_ds_ss_es(self)
            self.ql.hook_insn(self.hook_syscall, UC_X86_INS_SYSCALL)
            self.thread_class = QlLinuxX8664Thread

        if self.ql.shellcoder:
            if (self.ql.stack_address == 0):
                self.ql.stack_address = 0x1000000
            if (self.ql.stack_size == 0):
                self.ql.stack_size = 10 * 1024 * 1024
            self.ql.mem.map(self.ql.stack_address, self.ql.stack_size)
            self.ql.stack_address  = (self.ql.stack_address + 0x200000 - 0x1000)
            self.ql.mem.write(self.ql.stack_address, self.ql.shellcoder)
            
        else:
            if (self.ql.stack_address == 0):
                self.ql.stack_address = self.QL_LINUX_PREDEFINE_STACKADDRESS
            if (self.ql.stack_size == 0):
                self.ql.stack_size = self.QL_LINUX_PREDEFINE_STACKSIZE
            self.ql.mem.map(self.ql.stack_address, self.ql.stack_size)

        ql_setup_output(self.ql)


    def hook_syscall(self, int= None, intno= None):
        return self.load_syscall(intno)


    def run(self):
        self.ql.sp = self.ql.stack_address
        if (self.ql.until_addr == 0):
            self.ql.until_addr = self.QL_EMU_END

        try:
            if self.ql.shellcoder:
                self.ql.uc.emu_start(self.ql.stack_address, (self.ql.stack_address + len(self.ql.shellcoder)))
            else:
                if self.ql.multithread == True:
                    # start multithreading
                    thread_management = QlLinuxThreadManagement(self.ql)
                    self.ql.thread_management = thread_management
                    main_thread = self.thread_class(self.ql, thread_management, total_time = self.ql.timeout)
                    main_thread.store_regs()
                    main_thread.set_start_address(self.ql.loader.entry_point)
                    thread_management.set_main_thread(main_thread)

                    # enable lib patch
                    if self.ql.loader.elf_entry != self.ql.loader.entry_point:
                        main_thread.set_until_addr(self.ql.loader.elf_entry)
                        thread_management.run()
                        self.ql.enable_lib_patch()

                        main_thread.set_start_address(self.ql.loader.elf_entry)
                        main_thread.set_until_addr(self.ql.until_addr)
                        main_thread.running()

                        thread_management.clean_world()
                        thread_management.set_main_thread(main_thread)


                    thread_management.run()
                else:
                    if self.ql.loader.elf_entry != self.ql.loader.entry_point:
                        self.ql.uc.emu_start(self.ql.loader.entry_point, self.ql.loader.elf_entry, self.ql.timeout)
                        self.ql.enable_lib_patch()
                    self.ql.uc.emu_start(self.ql.loader.elf_entry, self.ql.until_addr, self.ql.timeout)

        except:
            if self.ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
                self.ql.nprint("[+] PC = 0x%x\n" %(self.ql.pc))
                self.ql.mem.show_mapinfo()
                try:
                    buf = self.ql.mem.read(self.ql.pc, 8)
                    self.ql.nprint("[+] %r" % ([hex(_) for _ in buf]))
                    self.ql.nprint("\n")
                    ql_hook_code_disasm(self.ql, self.ql.pc, 64)
                except:
                    pass
            raise

        if self.ql.internal_exception != None:
            raise self.ql.internal_exception
