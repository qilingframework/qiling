#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from unicorn import *
from unicorn.x86_const import *

from qiling.loader.elf import *
from qiling.arch.x86 import *

#from qiling.os.freebsd.x8664_syscall import map_syscall
# from qiling.os.posix.syscall import *
# from qiling.os.freebsd.syscall import *

from qiling.os.utils import *
from qiling.const import *
from qiling.os.freebsd.const import *
from qiling.os.const import *

class QlOsFreebsdManager:
    
    def __init__(self, ql):
        self.ql = ql

    def hook_syscall(self, intno= None):
        return self.ql.comm_os.load_syscall()

    def loader(self):
        """
        initiate UC needs to be in loader,
        or else it will kill execve
        """
        self.ql.uc = self.ql.init_Uc

        if (self.ql.stack_address == 0):
            if self.ql.shellcoder:
                self.ql.stack_address = 0x1000000
            else:
                self.ql.stack_address = QL_X8664_FREEBSD_PREDEFINE_STACKADDRESS
        
        if (self.ql.stack_size == 0):
            if self.ql.shellcoder:
                self.ql.stack_size = 10 * 1024 * 1024
            else:
                self.ql.stack_size = QL_X8664_FREEBSD_PREDEFINE_STACKSIZE
        
        self.ql.mem.map(self.ql.stack_address, self.ql.stack_size)
        
        if self.ql.shellcoder:
            self.ql.stack_address = self.ql.stack_address  + 0x200000 - 0x1000
        else:
            loader = ELFLoader(self.ql.path, self.ql)
            if loader.load_with_ld(self.ql, self.ql.stack_address + self.ql.stack_size, argv = self.ql.argv, env = self.ql.env):
                raise QlErrorFileType("Unsupported FileType")

            self.ql.stack_address = (int(self.ql.new_stack))


        init_rbp = self.ql.stack_address + 0x40
        init_rdi = self.ql.stack_address

        self.ql.register(UC_X86_REG_RSP, self.ql.stack_address)
        self.ql.register(UC_X86_REG_RBP, init_rbp)
        self.ql.register(UC_X86_REG_RDI, init_rdi)
        self.ql.register(UC_X86_REG_R14, init_rdi)

        #self.ql.dprint(0, "[+] RSP = 0x%x" % (self.ql.stack_address))
        #self.ql.dprint(0, "[+] RBP = 0x%x" % (init_rbp))
        #self.ql.dprint(0, "[+] RDI = 0x%x" % (init_rdi))

        ql_setup_output(self.ql)
        self.ql.hook_insn(self.hook_syscall, UC_X86_INS_SYSCALL)

        ql_x8664_setup_gdt_segment_cs(self.ql)
        ql_x8664_setup_gdt_segment_ss(self.ql)


    def runner(self):
        if (self.ql.until_addr == 0):
            self.ql.until_addr = QL_ARCHBIT64_EMU_END
        try:
            if self.ql.shellcoder:
                self.ql.uc.emu_start(self.ql.stack_address, (self.ql.stack_address + len(self.ql.shellcoder)))
            else:
                if self.ql.elf_entry != self.ql.entry_point:
                    self.ql.uc.emu_start(self.ql.entry_point, self.ql.elf_entry, self.ql.timeout) 
                    self.ql.enable_lib_patch()
                self.ql.uc.emu_start(self.ql.elf_entry, self.ql.until_addr, self.ql.timeout) 
                
        except UcError:
            if self.ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP, QL_OUT_DISASM):
                self.ql.nprint("[+] PC = 0x%x\n" %(self.ql.pc))
                self.ql.mem.show_mapinfo()
                try:
                    buf = self.ql.mem.read(self.ql.pc, 8)
                    self.ql.nprint("[+] %r" % ([hex(_) for _ in buf]))
                    self.ql.nprint("\n")
                    ql_hook_code_disasm(ql, self.ql.pc, 64)
                except:
                    pass
            raise
        
        if self.ql.internal_exception != None:
            raise self.ql.internal_exception
