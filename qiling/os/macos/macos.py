#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import traceback

from unicorn import *
from unicorn.x86_const import *
from unicorn.arm64_const import *

from qiling.loader.macho import *
from qiling.arch.x86 import *

from qiling.os.macos.utils import *
from qiling.os.macos.kernel_func import *
from qiling.os.macos.thread import *
from qiling.os.macos.subsystems import *
from qiling.os.macos.task import *
from qiling.os.macos.mach_port import *
from qiling.os.posix.syscall import *
from qiling.os.utils import *
from qiling.const import *
from qiling.os.const import *
from qiling.os.macos.const import *


class QlOsMacosManager:
    
    def __init__(self, ql):
        self.ql = ql


    def hook_syscall(self, intno= None, int = None):
        return self.ql.comm_os.load_syscall()
 

    def loader(self):
        """
        initiate UC needs to be in loader,
        or else it will kill execve
        """
        self.ql.uc = self.ql.init_Uc

        if self.ql.arch == QL_ARM64:
            self.QL_MACOS_PREDEFINE_STACKADDRESS        = 0x0000000160503000
            self.QL_MACOS_PREDEFINE_STACKSIZE           = 0x21000
            self.QL_MACOS_PREDEFINE_MMAPADDRESS         = 0x7ffbf0100000
            self.QL_MACOS_PREDEFINE_VMMAP_TRAP_ADDRESS  = 0x4000000f4000
        elif  self.ql.arch == QL_X8664:   
            self.QL_MACOS_PREDEFINE_STACKADDRESS        = 0x7ffcf0000000
            self.QL_MACOS_PREDEFINE_STACKSIZE           = 0x19a00000
            self.QL_MACOS_PREDEFINE_MMAPADDRESS         = 0x7ffbf0100000
            self.QL_MACOS_PREDEFINE_VMMAP_TRAP_ADDRESS  = 0x4000000f4000

        if self.ql.shellcoder:
            if (self.ql.stack_address == 0):
                self.ql.stack_address = 0x1000000
            if (self.ql.stack_size == 0): 
                self.ql.stack_size = 10 * 1024 * 1024
        else:
            if (self.ql.stack_address == 0):
                self.ql.stack_address = self.QL_MACOS_PREDEFINE_STACKADDRESS
            if (self.ql.stack_size == 0): 
                self.ql.stack_size = self.QL_MACOS_PREDEFINE_STACKSIZE        

        self.ql.macho_task = MachoTask()
        self.ql.macho_fs = FileSystem(self.ql)
        self.ql.macho_mach_port = MachPort(2187)
        self.ql.macho_port_manager = MachPortManager(self.ql, self.ql.macho_mach_port)
        self.ql.macho_host_server = MachHostServer(self.ql)
        self.ql.macho_task_server = MachTaskServer(self.ql)
        
        if self.ql.mmap_start == 0:
            self.ql.mmap_start = self.QL_MACOS_PREDEFINE_MMAPADDRESS
        
        if self.ql.shellcoder:
            self.ql.mem.map(self.ql.stack_address, self.ql.stack_size)
            self.ql.stack_address = self.ql.stack_address  + 0x200000 - 0x1000
            self.ql.mem.write(self.ql.stack_address, self.ql.shellcoder)
        else:
            self.ql.macho_vmmap_end = self.QL_MACOS_PREDEFINE_VMMAP_TRAP_ADDRESS
            self.ql.mem.map(self.ql.stack_address, self.ql.stack_size)
            stack_sp = self.QL_MACOS_PREDEFINE_STACKADDRESS + self.QL_MACOS_PREDEFINE_STACKSIZE
            envs = env_dict_to_array(self.ql.env)
            apples = ql_real_to_vm_abspath(self.ql, self.ql.path)
            loader = Macho(self.ql, self.ql.path, stack_sp, [self.ql.path], envs, apples, 1)
            loader.loadMacho()
            self.ql.macho_task.min_offset = page_align_end(loader.vm_end_addr, PAGE_SIZE)
            self.ql.stack_address = (int(self.ql.stack_sp))
        

    def runner(self):
        if self.ql.arch == QL_ARM64:
            self.ql.register(UC_ARM64_REG_SP, self.ql.stack_address)
            self.ql.archfunc.enable_vfp()
            self.ql.hook_intr(self.hook_syscall)
        
        elif self.ql.arch == QL_X8664:           
            self.ql.register(UC_X86_REG_RSP, self.ql.stack_address)
            self.ql.hook_insn(self.hook_syscall, UC_X86_INS_SYSCALL)

        if  self.ql.arch == QL_X8664:
            ql_x8664_setup_gdt_segment_ds(self.ql)
            ql_x8664_setup_gdt_segment_cs(self.ql)
            ql_x8664_setup_gdt_segment_ss(self.ql)
        
        ql_setup_output(self.ql)
        vm_shared_region_enter(self.ql)
        map_commpage(self.ql)
        self.ql.macho_thread = MachoThread()
        
        # load_commpage not wroking with QL_ARM64, yet
        if  self.ql.arch == QL_X8664:
            load_commpage(self.ql)
        
        if (self.ql.until_addr == 0):
            self.ql.until_addr = QL_ARCHBIT64_EMU_END
        try:
            if self.ql.shellcoder:
                self.ql.uc.emu_start(self.ql.stack_address, (self.ql.stack_address + len(self.ql.shellcoder)))
            else:
                self.ql.uc.emu_start(self.ql.entry_point, self.ql.until_addr, self.ql.timeout)
        except UcError:
            if self.ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
                self.ql.nprint("[+] PC= " + hex(self.ql.pc))
                self.ql.mem.show_mapinfo()
                buf = self.ql.mem.read(self.ql.pc, 8)
                self.ql.nprint("[+] ", [hex(_) for _ in buf])
                ql_hook_code_disasm(self.ql, self.ql.pc, 64)
            raise QlErrorExecutionStop("[!] Execution Terminated")    
        
        if self.ql.internal_exception != None:
            raise self.ql.internal_exception  
