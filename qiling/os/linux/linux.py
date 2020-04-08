#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from unicorn import *

from unicorn.arm_const import *
from unicorn.x86_const import *
from unicorn.arm64_const import *
from unicorn.mips_const import *

from qiling.loader.elf import *
from qiling.arch.x86 import *

from qiling.os.linux.const import *
from qiling.os.linux.utils import *
from qiling.os.utils import *
from qiling.const import *

from qiling.arch.x86 import *

from qiling.os.posix.posix import QlOsPosix

class QlOsLinux(QlOsPosix):
    def __init__(self, ql):
        super(QlOsLinux, self).__init__(ql)
        self.ql = ql
        self.QL_LINUX_PREDEFINE_STACKSIZE = 0x21000
        self.QL_ARM_KERNEL_GET_TLS_ADDR = 0xFFFF0FE0
        self.ql.os = self
        self.load()

    def load(self):   
        """
        initiate UC needs to be in loader,
        or else it will kill execve
        """
        self.ql.uc = self.ql.init_Uc
        
        # ARM
        if self.ql.archtype== QL_ARM:
            self.QL_LINUX_PREDEFINE_STACKADDRESS = 0xfff0d000 
            self.ql.arch.enable_vfp()
            ql_arm_init_kernel_get_tls(self.ql)
            self.ql.hook_intr(self.hook_syscall)
    
        # MIPS32 
        elif self.ql.archtype== QL_MIPS32:
            self.QL_LINUX_PREDEFINE_STACKADDRESS = 0x7ff0d000 
            self.QL_LINUX_PREDEFINE_STACKSIZE = 0x30000  
            self.ql.hook_intr(self.hook_syscall)                
    
        # ARM64        
        elif self.ql.archtype== QL_ARM64:
            self.QL_LINUX_PREDEFINE_STACKADDRESS = 0x7ffffffde000
            self.ql.arch.enable_vfp()
            self.ql.hook_intr(self.hook_syscall)
    
        # X86        
        elif  self.ql.archtype== QL_X86:
            self.QL_LINUX_PREDEFINE_STACKADDRESS = 0xfffdd000
            ql_x86_setup_gdt_segment_ds(self.ql)
            ql_x86_setup_gdt_segment_cs(self.ql)
            ql_x86_setup_gdt_segment_ss(self.ql)
            self.ql.hook_intr(self.hook_syscall)
    
        # X8664            
        elif  self.ql.archtype== QL_X8664:
            self.QL_LINUX_PREDEFINE_STACKADDRESS = 0x7ffffffde000
            ql_x8664_setup_gdt_segment_ds(self.ql)
            ql_x8664_setup_gdt_segment_cs(self.ql)
            ql_x8664_setup_gdt_segment_ss(self.ql)
            self.ql.hook_insn(self.hook_syscall, UC_X86_INS_SYSCALL)
        
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
            loader = ELFLoader(self.ql.path, self.ql)
            if loader.load_with_ld(self.ql, self.ql.stack_address + self.ql.stack_size, argv = self.ql.argv,  env = self.ql.env):
                raise QlErrorFileType("Unsupported FileType")
            self.ql.stack_address  = (int(self.ql.new_stack))
        
        self.ql.sp = self.ql.stack_address
        ql_setup_output(self.ql)


    def hook_syscall(self, int= None, intno= None):
        return self.load_syscall(intno)

    
    def run(self):


        if (self.ql.until_addr == 0):
            if self.ql.archbit == 32:
                self.ql.until_addr = QL_ARCHBIT32_EMU_END
            elif self.ql.archbit == 64:
                self.ql.until_addr = QL_ARCHBIT64_EMU_END           

        try:
            if self.ql.shellcoder:
                self.ql.uc.emu_start(self.ql.stack_address, (self.ql.stack_address + len(self.ql.shellcoder)))
            else:
                if self.ql.multithread == True:        
                    # start multithreading
                    thread_management = ThreadManagement(ql)
                    self.ql.thread_management = thread_management
                    
                    if self.ql.archtype== QL_ARM:
                        thread_set_tls = arm_thread_set_tls
                    elif self.ql.archtype== QL_MIPS32:
                        thread_set_tls = mips32_thread_set_tls
                    elif self.ql.archtype== QL_X86:
                        thread_set_tls = x86_thread_set_tls                    
                    else:
                        thread_set_tls = None
                    
                    main_thread = Thread(self.ql, thread_management, total_time = self.ql.timeout, special_settings_fuc = thread_set_tls)
                    
                    main_thread.save()
                    main_thread.set_start_address(self.ql.entry_point)

                    thread_management.set_main_thread(main_thread)
                
                    # enable lib patch
                    if self.ql.elf_entry != self.ql.entry_point:
                        main_thread.set_until_addr(self.ql.elf_entry)
                        thread_management.run()
                        self.ql.enable_lib_patch()
                        
                        main_thread.set_start_address(self.ql.elf_entry)
                        main_thread.set_until_addr(self.ql.until_addr)
                        main_thread.running()
                        
                        thread_management.clean_world()
                        thread_management.set_main_thread(main_thread)


                    thread_management.run() 
                else:
                    if self.ql.elf_entry != self.ql.entry_point:
                        self.ql.uc.emu_start(self.ql.entry_point, self.ql.elf_entry, self.ql.timeout) 
                        self.ql.enable_lib_patch()
                    self.ql.uc.emu_start(self.ql.elf_entry, self.ql.until_addr, self.ql.timeout) 

        except:
            if self.ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
                self.ql.nprint("[+] PC = 0x%x\n" %(self.ql.pc))
                self.ql.mem.show_mapinfo()
                try:
                    buf = self.ql.mem.read(ql.pc, 8)
                    self.ql.nprint("[+] %r" % ([hex(_) for _ in buf]))
                    self.ql.nprint("\n")
                    self.ql_hook_code_disasm(ql, ql.pc, 64)
                except:
                    pass
            raise
        
        if self.ql.internal_exception != None:
            raise self.ql.internal_exception