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
        self.QL_ARM_KERNEL_GET_TLS_ADDR = 0xFFFF0FE0
        self.thread_class = None
        self.futexm = None
        self.fh_tmp = []
        self.fh = None
        self.load()

    def load(self):
        self.ql.uc = self.ql.arch.init_uc
        self.futexm = QlLinuxFutexManagement()

        if self.ql.archbit == 32:
            stack_address = int(self.profile.get("OS32", "stack_address"),16)
            stack_size = int(self.profile.get("OS32", "stack_size"),16)
        elif self.ql.archbit == 64:
            stack_address = int(self.profile.get("OS64", "stack_address"),16)
            stack_size = int(self.profile.get("OS64", "stack_size"),16)

        # ARM
        if self.ql.archtype== QL_ARCH.ARM:
            self.ql.arch.enable_vfp()
            self.ql.hook_intno(self.hook_syscall, 2)
            self.thread_class = QlLinuxARMThread

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

        if self.ql.shellcoder:
            self.ql.mem.map(self.entry_point, self.shellcoder_ram_size, info="[shellcode_stack]")
            self.entry_point  = (self.entry_point + 0x200000 - 0x1000)
            self.ql.mem.write(self.entry_point, self.ql.shellcoder)
        else:
            # if not self.ql.stack_address and not self.ql.stack_size:
            self.stack_address = stack_address
            self.stack_size = stack_size
            # elif self.ql.stack_address and self.ql.stack_size:
            #     self.stack_address = self.ql.stack_address
            #     self.stack_address = self.ql.stack_size    

            self.ql.mem.map(self.stack_address, self.stack_size, info="[stack]")            

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
        
        if self.ql.shellcoder:
            self.ql.reg.arch_sp = self.entry_point
        else:            
            self.ql.reg.arch_sp = self.stack_address

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
                    
                    if  self.ql.entry_point is not None:
                        self.ql.loader.elf_entry = self.ql.entry_point
                    
                    self.ql.emu_start(self.ql.loader.elf_entry, self.exit_point, self.ql.timeout, self.ql.count)

        except:
            if self.ql.output in (QL_OUTPUT.DEBUG, QL_OUTPUT.DUMP):
                self.ql.nprint("[+] PC = 0x%x\n" %(self.ql.reg.arch_pc))
                self.ql.mem.show_mapinfo()
                buf = self.ql.mem.read(self.ql.reg.arch_pc, 8)
                self.ql.nprint("[+] %r" % ([hex(_) for _ in buf]))
                self.ql.nprint("\n")
                self.disassembler(self.ql, self.ql.reg.arch_pc, 64)
            raise

        if self.ql.internal_exception != None:
            raise self.ql.internal_exception
