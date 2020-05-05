#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import traceback

from unicorn import *
from unicorn.x86_const import *
from unicorn.arm64_const import *

from qiling.arch.x86 import *

from qiling.const import *
from qiling.os.const import *
from qiling.os.posix.posix import QlOsPosix

from .utils import *
from .kernel_func import *
from .thread import *
from .subsystems import *
from .task import *
from .mach_port import *
from .const import *

class QlOsMacos(QlOsPosix):
    def __init__(self, ql):
        super(QlOsMacos, self).__init__(ql)
        self.ql = ql
        self.env = self.ql.env
        self.argv = self.ql.argv
        self.load()

    def load(self):

        self.ql.uc = self.ql.arch.init_uc
        stack_address        = int(self.profile.get("OS64", "stack_address"),16)
        stack_size           = int(self.profile.get("OS64", "stack_size"),16)     
        vmmap_trap_address  = int(self.profile.get("OS64", "vmmap_trap_address"),16)
        self.stack_address = stack_address
        self.stack_size = stack_size            

        if self.ql.shellcoder:    
            self.ql.mem.map(self.entry_point, self.shellcoder_ram_size, info="[shellcode_stack]")
            self.entry_point  = (self.entry_point + 0x200000 - 0x1000)
            self.ql.mem.write(self.entry_point, self.ql.shellcoder)
        else:
            self.macho_task = MachoTask()
            self.macho_fs = FileSystem(self.ql)
            self.macho_mach_port = MachPort(2187)
            self.macho_port_manager = MachPortManager(self.ql, self.macho_mach_port)
            self.macho_host_server = MachHostServer(self.ql)
            self.macho_task_server = MachTaskServer(self.ql)
            self.ql.mem.map(self.stack_address, self.stack_size, info="[stack]")
            self.ql.macho_vmmap_end = vmmap_trap_address
            self.stack_sp = stack_address + stack_size
            self.envs = env_dict_to_array(self.env)
            self.apples = ql_real_to_vm_abspath(self.ql, self.ql.path)

    def hook_syscall(self, intno= None, int = None):
        return self.load_syscall()


    def run(self):
        if self.ql.exit_point is not None:
            self.exit_point = self.ql.exit_point
        
        if  self.ql.entry_point is not None:
                self.ql.loader.elf_entry = self.ql.entry_point    

        if self.ql.shellcoder:
            self.ql.reg.arch_sp = self.entry_point
        else:            
            self.ql.reg.arch_sp = self.ql.loader.stack_address

        if self.ql.archtype== QL_ARCH.ARM64:
            self.ql.arch.enable_vfp()
            self.ql.hook_intno(self.hook_syscall, 2)

        elif self.ql.archtype== QL_ARCH.X8664:
            self.ql.hook_insn(self.hook_syscall, UC_X86_INS_SYSCALL)
            self.gdtm = GDTManager(self.ql)
            ql_x86_register_cs(self)
            ql_x86_register_ds_ss_es(self)
                
        if not self.ql.shellcoder:
            self.macho_task.min_offset = page_align_end(self.ql.loader.vm_end_addr, PAGE_SIZE)
    
            # FIXME: Not working due to overlarge mapping, need to fix it
            # vm_shared_region_enter(self.ql)
            
            map_commpage(self.ql)
            
            self.thread_management = QlMachoThreadManagement(self.ql)
            self.macho_thread = QlMachoThread(self.ql)
            self.thread_management.cur_thread = self.macho_thread

            # load_commpage not wroking with ARM64, yet
            if  self.ql.archtype== QL_ARCH.X8664:
                load_commpage(self.ql)
        
        self.setup_output()                
        
        try:
            if self.ql.shellcoder:
                self.ql.emu_start(self.entry_point, (self.entry_point + len(self.ql.shellcoder)), self.ql.timeout, self.ql.count)
            else:
                self.ql.emu_start(self.ql.loader.entry_point, self.exit_point, self.ql.timeout, self.ql.count)
        except UcError:
            if self.ql.output in (QL_OUTPUT.DEBUG, QL_OUTPUT.DUMP):
                self.ql.nprint("[+] PC= " + hex(self.ql.reg.arch_pc))
                self.ql.mem.show_mapinfo()
                buf = self.ql.mem.read(self.ql.reg.arch_pc, 8)
                self.ql.nprint("[+] %r" % ([hex(_) for _ in buf]))
                self.ql.nprint("\n")
                self.disassembler(self.ql, self.ql.reg.arch_pc, 64)
            raise QlErrorExecutionStop("[!] Execution Terminated")

        if self.ql.internal_exception != None:
            raise self.ql.internal_exception
