#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import os, struct

from .loader import QlLoader

from qiling.exception import *
from qiling.const import *

from .macho_parser.parser import *
from .macho_parser.const import *

from qiling.os.macos.const import *
from qiling.os.macos.task import MachoTask
from qiling.os.macos.kernel_func import FileSystem, map_commpage
from qiling.os.macos.mach_port import MachPort, MachPortManager
from qiling.os.macos.subsystems import MachHostServer, MachTaskServer
from qiling.os.macos.utils import env_dict_to_array, ql_real_to_vm_abspath, page_align_end
from qiling.os.macos.thread import QlMachoThreadManagement, QlMachoThread

# commpage is a shared mem space which is in a static address
def load_commpage(ql):
    if ql.archtype == QL_ARCH.X8664:
        COMM_PAGE_START_ADDRESS = X8664_COMM_PAGE_START_ADDRESS
    else:    
        COMM_PAGE_START_ADDRESS = ARM64_COMM_PAGE_START_ADDRESS

    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_SIGNATURE, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_CPU_CAPABILITIES64, b'\x00\x00\x00\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_UNUSED, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_VERSION, b'\x0d')
    ql.mem.write(COMM_PAGE_THIS_VERSION, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_CPU_CAPABILITIES, b'\x00\x00\x00\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_NCPUS, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_UNUSED0, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_CACHE_LINESIZE, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_SCHED_GEN, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_MEMORY_PRESSURE, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_SPIN_COUNT, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_ACTIVE_CPUS, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_PHYSICAL_CPUS, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_LOGICAL_CPUS, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_UNUSED1, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_MEMORY_SIZE, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_CPUFAMILY, b'\xec\x5e\x3b\x57')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_KDEBUG_ENABLE, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_ATM_DIAGNOSTIC_CONFIG, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_UNUSED2, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_TIME_DATA_START, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_NT_TSC_BASE, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_NT_SCALE, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_NT_SHIFT, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_NT_NS_BASE, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_NT_GENERATION, b'\x01')       # someflag seem important 
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_GTOD_GENERATION, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_GTOD_NS_BASE, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_GTOD_SEC_BASE, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_APPROX_TIME, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_APPROX_TIME_SUPPORTED, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_CONT_TIMEBASE, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_BOOTTIME_USEC, b'\x00')


class QlLoaderMACHO(QlLoader):
    # macho x8664 loader 
    def __init__(self, ql, dyld_path=None):
        super(QlLoaderMACHO, self).__init__(ql)
        self.dyld_path      = dyld_path
        self.ql             = ql
    
    def run(self):
        self.profile        = self.ql.profile
        stack_address      = int(self.profile.get("OS64", "stack_address"), 16)
        stack_size         = int(self.profile.get("OS64", "stack_size"), 16)
        vmmap_trap_address = int(self.profile.get("OS64", "vmmap_trap_address"), 16)
        self.stack_address = stack_address
        self.stack_size = stack_size

        if self.ql.shellcoder:
            self.ql.mem.map(self.ql.os.entry_point, self.ql.os.shellcoder_ram_size, info="[shellcode_stack]")
            self.ql.os.entry_point  = (self.ql.os.entry_point + 0x200000 - 0x1000)
            
            # for ASM file input, will mem.write in qltools
            try:
                self.ql.mem.write(self.entry_point, self.ql.shellcoder)
            except:
                pass

            self.ql.reg.arch_sp = self.ql.os.entry_point
            return
        
        self.ql.os.macho_task = MachoTask()
        self.ql.os.macho_fs = FileSystem(self.ql)
        self.ql.os.macho_mach_port = MachPort(2187)
        self.ql.os.macho_port_manager = MachPortManager(self.ql, self.ql.os.macho_mach_port)
        self.ql.os.macho_host_server = MachHostServer(self.ql)
        self.ql.os.macho_task_server = MachTaskServer(self.ql)
        
        self.envs = env_dict_to_array(self.env)
        self.apples = ql_real_to_vm_abspath(self.ql, self.ql.path)

        # FIXME: Not working due to overlarge mapping, need to fix it
        # vm_shared_region_enter(self.ql)

        map_commpage(self.ql)

        self.ql.os.thread_management = QlMachoThreadManagement(self.ql)
        self.ql.os.macho_thread = QlMachoThread(self.ql)
        self.ql.os.thread_management.cur_thread = self.ql.os.macho_thread
        self.ql.os.macho_vmmap_end = vmmap_trap_address
        self.stack_sp = stack_address + stack_size
        self.macho_file     = MachoParser(self.ql, self.ql.path)
        self.loading_file   = self.macho_file
        self.slide          = int(self.profile.get("LOADER", "slide"), 16)
        self.dyld_slide     = int(self.profile.get("LOADER", "dyld_slide"), 16)
        self.string_align   = 8
        self.ptr_align      = 8
        self.binary_entry   = 0x0
        self.proc_entry     = 0x0
        self.argvs          = [self.ql.path]
        self.argc           = 1
        self.using_dyld     = False
        self.vm_end_addr    = 0x0
        self.ql.mem.map(self.stack_address, self.stack_size, info="[stack]")
        self.loadMacho()
        self.stack_address = (int(self.stack_sp))
        self.ql.reg.arch_sp = self.stack_address # self.stack_sp
        self.ql.os.macho_task.min_offset = page_align_end(self.vm_end_addr, PAGE_SIZE)

    def loadMacho(self, depth=0, isdyld=False):
        mmap_address   = int(self.profile.get("OS64", "mmap_address"), 16)

        # MAX load depth 
        if depth > 5:
            return

        # three pass 
        # 1: unixthread, uuid, code signature
        # 2: segment
        # 3: dyld
        for pass_count in range(1, 4):

            if isdyld:
                cmds = self.dyld_file.commands
            else:
                cmds = self.macho_file.commands

            for cmd in cmds:
                if pass_count == 1:
                    if cmd.cmd_id == LC_UNIXTHREAD:
                        self.loadUnixThread(cmd, isdyld)

                    if cmd.cmd_id == LC_UUID:
                        self.loadUuid()

                    if cmd.cmd_id == LC_CODE_SIGNATURE:
                        self.loadCodeSignature()

                    if cmd.cmd_id == LC_MAIN:
                        self.loadMain(cmd)

                if pass_count == 2:
                    if cmd.cmd_id == LC_SEGMENT:
                        pass

                    if cmd.cmd_id == LC_SEGMENT_64:
                        self.loadSegment64(cmd, isdyld)

                if pass_count == 3:
                    if cmd.cmd_id == LC_LOAD_DYLINKER:
                        self.loadDylinker(cmd)
                        self.using_dyld = True
                        if not isdyld:
                            if not self.dyld_path:
                                raise QlErrorMACHOFormat("[!] Error No Dyld path")
                            self.dyld_path =  os.path.join(self.ql.rootfs + self.dyld_path)
                            self.dyld_file = MachoParser(self.ql, self.dyld_path)
                            self.loading_file = self.dyld_file
                            self.proc_entry = self.loadMacho(depth + 1, True)
                            self.loading_file = self.macho_file
                            self.using_dyld = True

        if depth == 0:
            self.mmap_address = mmap_address
            self.stack_sp = self.loadStack()
            if self.using_dyld:
                self.ql.nprint("[+] ProcEntry: {}".format(hex(self.proc_entry)))
                self.entry_point = self.proc_entry + self.dyld_slide
                self.ql.nprint("[+] Dyld entry point: {}".format(hex(self.entry_point)))
            else:
                self.entry_point = self.proc_entry + self.slide
            self.ql.nprint("[+] Binary Entry Point: 0x{:X}".format(self.binary_entry))
            self.macho_entry = self.binary_entry + self.slide
            self.load_address = self.macho_entry

        # load_commpage not wroking with ARM64, yet
        if  self.ql.archtype== QL_ARCH.X8664:
            load_commpage(self.ql)

        return self.proc_entry
        
    def loadSegment64(self, cmd, isdyld):
        PAGE_SIZE = 0x1000
        if isdyld:
            slide = self.dyld_slide
        else:
            slide = self.slide
        vaddr_start = cmd.vm_address + slide
        vaddr_end = cmd.vm_address + cmd.vm_size + slide 
        seg_size = cmd.vm_size
        seg_name = cmd.segment_name
        seg_data = bytes(self.loading_file.get_segment(seg_name).content)

        if seg_name[:10] == "__PAGEZERO":
            self.ql.dprint(D_INFO, "[+] Now loading {}, VM[{}:{}] for pagezero actually it only got a page size".format(seg_name, hex(vaddr_start), hex(vaddr_end)))
            self.ql.mem.map(vaddr_start, PAGE_SIZE, info="[__PAGEZERO]")
            self.ql.mem.write(vaddr_start, b'\x00' * PAGE_SIZE)
            if self.vm_end_addr < vaddr_end:
                self.vm_end_addr = vaddr_end
        else:
            self.ql.dprint(D_INFO, "[+] Now loading {}, VM[{}:{}]".format(seg_name, hex(vaddr_start), hex(vaddr_end)))
            self.ql.mem.map(vaddr_start, seg_size,  info="[loadSegment64]")
            self.ql.mem.write(vaddr_start, seg_data)
            if self.vm_end_addr < vaddr_end:
                self.vm_end_addr = vaddr_end
    
    def loadUnixThread(self, cmd, isdyld):
        if not isdyld:
            self.binary_entry = cmd.entry
 
        self.proc_entry = cmd.entry
        self.ql.dprint(D_INFO, "[+] Binary Thread Entry: {}".format(hex(cmd.entry)))


    def loadUuid(self):
        # todo: WIP
        pass

    def loadCodeSignature(self):
        # todo: WIP
        pass
    
    def loadMain(self, cmd, isdyld=False):
        if self.macho_file.page_zero_size:
            if not isdyld:
                self.binary_entry = cmd.entry_offset + self.macho_file.page_zero_size
            self.proc_entry = cmd.entry_offset + self.macho_file.page_zero_size

    def loadDylinker(self, cmd):
        self.dyld_path = cmd.name

    def make_string(self, argvs, envs, apple_str):
        result = bytes()
        for item in apple_str:
            b = bytes(item, encoding='utf8') + b'\x00'
            result = b +result
        for item in envs:
            b = bytes(item, encoding='utf8') + b'\x00'
            result = b +result 
        for item in argvs:
            b = bytes(item, encoding='utf8') + b'\x00'
            result = b +result
        return result 

    # TODO: add size check
    def loadStack(self):

        argvs_ptr = []
        envs_ptr = []
        apple_ptr = []

        all_str = self.make_string(self.argvs, self.envs, self.apples)
        self.push_stack_string(all_str)
        ptr = self.stack_sp

        for item in self.argvs[::-1]:
            argvs_ptr.append(ptr)  # need pack and tostring
            self.ql.dprint(D_INFO, '[+] add argvs ptr {}'.format(hex(ptr)))
            ptr += len(item) + 1
        
        for item in self.envs[::-1]:
            envs_ptr.append(ptr)
            self.ql.dprint(D_INFO, '[+] add envs ptr {}'.format(hex(ptr)))
            ptr += len(item) + 1

        for item in self.apples[::-1]:
            apple_ptr.append(ptr)
            self.ql.dprint(D_INFO, '[+] add apple ptr {}'.format(hex(ptr)))
            ptr += len(item) + 1

        ptr = self.stack_sp
        self.push_stack_addr(0x0)
        ptr -= 4
        
        for item in apple_ptr:
            self.push_stack_addr(item)
            ptr -= 4
        
        self.push_stack_addr(0x0)
        ptr -= 4
        
        for item in envs_ptr:
            ptr -= 4
            self.push_stack_addr(item)

        self.push_stack_addr(0x0)
        ptr -= 4
        
        for item in argvs_ptr:
            ptr -= 4
            self.push_stack_addr(item)
            self.ql.dprint(D_INFO, "[+] SP 0x%x, content 0x%x" % (self.stack_sp, item))
        argvs_ptr_ptr = ptr 

        self.push_stack_addr(self.argc)
        ptr -= 4
        self.ql.dprint(D_INFO, "[+] SP 0x%x, content 0x%x" % (self.stack_sp, self.argc))
       
        if self.using_dyld:
            ptr -= 4
            #self.ql.nprint("[+] Binary Dynamic Entry Point: {:X}".format(self.binary_entry))
            self.push_stack_addr(self.macho_file.header_address)
            # self.push_stack_addr(self.binary_entry)

        return self.stack_sp

    def push_stack_string(self, data):
        align = self.string_align
        length = len(data)
        
        if length % align != 0:
            for i in range(align - (length % align)):
                data += b'\x00' 
            length = len(data)
        
        self.stack_sp -= length
        self.ql.mem.write(self.stack_sp, data)
        self.ql.dprint(D_INFO, "[+] SP {} write data len {}".format(hex(self.stack_sp), length))
        
        return self.stack_sp
    
    def push_stack_addr(self, data):
        align = self.ptr_align
        
        if data == 0:
            content = b'\x00\x00\x00\x00\x00\x00\x00\x00'
        else:
            content = struct.pack('<Q', data)

        if len(content) != align:
            self.ql.nprint('[!] stack align error')
            return 
        
        self.stack_sp -= align
        self.ql.mem.write(self.stack_sp, content)

        return self.stack_sp
