#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from qiling.arch.x86 import *
from qiling.const import *
from qiling.os.const import *
from qiling.os.posix.posix import QlOsPosix
from .const import *

class QlOsFreebsd(QlOsPosix):
    def __init__(self, ql):
        super(QlOsFreebsd, self).__init__(ql)
        self.load()
        
    def load(self):   
        
        self.ql.uc = self.ql.arch.init_uc
        self.QL_FREEBSD_PREDEFINE_STACKADDRESS = 0x7ffffffde000
        self.QL_FREEBSD_PREDEFINE_STACKSIZE = 0x21000

        if self.ql.shellcoder:
            self.entry_point = 0x1000000
            self.shellcoder_ram = 10 * 1024 * 1024
            self.ql.mem.map(self.entry_point, self.shellcoder_ram, info="[shellcode_stack]")
            self.entry_point  = (self.entry_point + 0x200000 - 0x1000)
            self.ql.mem.write(self.entry_point, self.ql.shellcoder)
        else:
            if not self.ql.stack_address and not self.ql.stack_size:
                self.stack_address = self.QL_FREEBSD_PREDEFINE_STACKADDRESS
                self.stack_size = self.QL_FREEBSD_PREDEFINE_STACKSIZE
            elif self.ql.stack_address and self.ql.stack_size:
                self.stack_address = self.ql.stack_address
                self.stack_address = self.ql.stack_size    

            self.ql.mem.map(self.stack_address, self.stack_size, info="[stack]")                    
        
        if self.ql.shellcoder:
            self.ql.reg.sp = self.entry_point
        else:            
            self.ql.reg.sp = self.stack_address
            init_rbp = self.stack_address + 0x40
            init_rdi = self.stack_address
            self.ql.register(UC_X86_REG_RBP, init_rbp)
            self.ql.register(UC_X86_REG_RDI, init_rdi)
            self.ql.register(UC_X86_REG_R14, init_rdi)

        self.setup_output()
        self.ql.hook_insn(self.hook_syscall, UC_X86_INS_SYSCALL)

        self.gdtm = GDTManager(self.ql)
        ql_x86_register_cs(self)
        ql_x86_register_ds_ss_es(self)
        
    def hook_syscall(self, intno= None):
        return self.load_syscall()


    def run(self):
        if self.ql.exit_point is not None:
            self.exit_point = self.ql.exit_point

        if  self.ql.entry_point is not None:
            self.ql.loader.elf_entry = self.ql.entry_point            
        
        try:
            if self.ql.shellcoder:
                self.ql.emu_start(self.entry_point, (self.entry_point + len(self.ql.shellcoder)), self.ql.timeout, self.ql.count)
            else:
                if self.ql.loader.elf_entry != self.ql.loader.entry_point:
                    self.ql.emu_start(self.ql.loader.entry_point, self.ql.loader.elf_entry, self.ql.timeout)
                    self.ql.enable_lib_patch()
                

                                        
                self.ql.emu_start(self.ql.loader.elf_entry, self.exit_point, self.ql.timeout, self.ql.count)
                
        except UcError:
            if self.ql.output in (QL_OUTPUT.DEBUG, QL_OUTPUT.DUMP, QL_OUTPUT.DISASM):
                self.ql.nprint("[+] PC = 0x%x\n" %(self.ql.reg.pc))
                self.ql.mem.show_mapinfo()
                buf = self.ql.mem.read(self.ql.reg.pc, 8)
                self.ql.nprint("[+] %r" % ([hex(_) for _ in buf]))
                self.ql.nprint("\n")
                self.disassembler(self.ql, self.ql.reg.pc, 64)
            raise
        
        if self.ql.internal_exception != None:
            raise self.ql.internal_exception
