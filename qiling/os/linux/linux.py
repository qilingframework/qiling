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
        self.QL_LINUX_PREDEFINE_STACKSIZE = 0x21000
        self.QL_ARM_KERNEL_GET_TLS_ADDR = 0xFFFF0FE0
        self.thread_class = None
        self.futexm = None
        self.fh_tmp = []
        self.fh = None
        self.load()

    def load(self):

        self.ql.uc = self.ql.arch.init_uc
        self.futexm = QlLinuxFutexManagement()

        # ARM
        if self.ql.archtype== QL_ARCH.ARM:
            self.QL_LINUX_PREDEFINE_STACKADDRESS = 0xfff0d000
            self.ql.arch.enable_vfp()
            self.ql.hook_intno(self.hook_syscall, 2)
            self.thread_class = QlLinuxARMThread

        # MIPS32
        elif self.ql.archtype== QL_ARCH.MIPS32:
            self.QL_LINUX_PREDEFINE_STACKADDRESS = 0x7ff0d000
            self.QL_LINUX_PREDEFINE_STACKSIZE = 0x30000
            self.ql.hook_intno(self.hook_syscall, 17)
            self.thread_class = QlLinuxMIPS32Thread

        # ARM64
        elif self.ql.archtype== QL_ARCH.ARM64:
            self.QL_LINUX_PREDEFINE_STACKADDRESS = 0x7ffffffde000
            self.ql.arch.enable_vfp()
            self.ql.hook_intno(self.hook_syscall, 2)
            self.thread_class = QlLinuxARM64Thread

        # X86
        elif  self.ql.archtype== QL_ARCH.X86:
            self.QL_LINUX_PREDEFINE_STACKADDRESS = 0xfffdd000
            self.gdtm = GDTManager(self.ql)
            ql_x86_register_cs(self)
            ql_x86_register_ds_ss_es(self)
            self.ql.hook_intno(self.hook_syscall, 0x80)
            self.thread_class = QlLinuxX86Thread

        # X8664
        elif  self.ql.archtype== QL_ARCH.X8664:
            self.QL_LINUX_PREDEFINE_STACKADDRESS = 0x7ffffffde000
            self.gdtm = GDTManager(self.ql)
            ql_x86_register_cs(self)
            ql_x86_register_ds_ss_es(self)
            self.ql.hook_insn(self.hook_syscall, UC_X86_INS_SYSCALL)
            self.thread_class = QlLinuxX8664Thread

        if self.ql.shellcoder and not self.ql.stack_address and not self.ql.stack_size:
            self.stack_address = 0x1000000
            self.stack_size = 10 * 1024 * 1024

        elif not self.ql.shellcoder and not self.ql.stack_address and not self.ql.stack_size:
            self.stack_address = self.QL_LINUX_PREDEFINE_STACKADDRESS
            self.stack_size = self.QL_LINUX_PREDEFINE_STACKSIZE

        elif self.ql.stack_address and self.ql.stack_size:
            self.stack_address = self.ql.stack_address
            self.stack_address = self.ql.stack_size                
        
        self.ql.mem.map(self.stack_address, self.stack_size, info="[stack]")
        
        if self.ql.shellcoder:
            self.stack_address  = (self.stack_address + 0x200000 - 0x1000)
            self.ql.mem.write(self.stack_address, self.ql.shellcoder)

        self.setup_output()


    def hook_syscall(self, int= None, intno= None):
        return self.load_syscall(intno)

    def add_function_hook(self, fn, cb, userdata = None):
        self.fh_tmp.append((fn, cb, userdata))

    def run(self):
        for fn, cb, userdata in self.fh_tmp:
            self.fh.add_function_hook(fn, cb, userdata)

        if self.ql.archtype== QL_ARCH.ARM:
            ql_arm_init_kernel_get_tls(self.ql)
        
        self.ql.reg.sp = self.stack_address

        if (self.ql.until_addr == 0):
            self.ql.until_addr = self.QL_EMU_END

        try:
            if self.ql.shellcoder:
                self.ql.emu_start(self.stack_address, (self.stack_address + len(self.ql.shellcoder)))
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
                        self.ql.emu_start(self.ql.loader.entry_point, self.ql.loader.elf_entry, self.ql.timeout)
                        self.ql.enable_lib_patch()
                    self.ql.emu_start(self.ql.loader.elf_entry, self.ql.until_addr, self.ql.timeout)

        except:
            if self.ql.output in (QL_OUTPUT.DEBUG, QL_OUTPUT.DUMP):
                self.ql.nprint("[+] PC = 0x%x\n" %(self.ql.reg.pc))
                self.ql.mem.show_mapinfo()
                try:
                    buf = self.ql.mem.read(self.ql.reg.pc, 8)
                    self.ql.nprint("[+] %r" % ([hex(_) for _ in buf]))
                    self.ql.nprint("\n")
                    ql_hook_code_disasm(self.ql, self.ql.reg.pc, 64)
                except:
                    pass
            raise

        if self.ql.internal_exception != None:
            raise self.ql.internal_exception
