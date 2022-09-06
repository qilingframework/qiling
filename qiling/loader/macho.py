#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os, plistlib, struct

from .loader import QlLoader

from qiling.exception import *
from qiling.const import *

from .macho_parser.parser import *
from .macho_parser.const import *
from .macho_parser.utils import *
from qiling.os.macos.kernel_api.hook import *
from qiling.os.memory import QlMemoryHeap

from qiling.os.macos.const import *
from qiling.os.macos.task import MachoTask
from qiling.os.macos.kernel_func import FileSystem, map_commpage
from qiling.os.macos.mach_port import MachPort, MachPortManager
from qiling.os.macos.subsystems import MachHostServer, MachTaskServer
from qiling.os.macos.utils import env_dict_to_array, page_align_end
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

        #FIXME: Demigod needs a better way to handle kext file
        if os.path.isdir(self.ql.argv[0]):
            basename = os.path.basename(self.ql.argv[0])
            self.kext_name = os.path.splitext(basename)[0]
            filename = self.ql.argv
            self.ql._argv = [self.ql.argv[0] + "/Contents/MacOS/" + self.kext_name]
            self.ql._path = self.ql.argv[0]
            self.plist = plistlib.load(open(filename[0] + "/Contents/Info.plist", "rb"))
            if "IOKitPersonalities" in self.plist:
                self.IOKit = True
            else:
                self.IOKit = False
        else:
            self.kext_name = None        
    
    def run(self):
        self.profile        = self.ql.profile
        stack_address      = int(self.profile.get("OS64", "stack_address"), 16)
        stack_size         = int(self.profile.get("OS64", "stack_size"), 16)
        vmmap_trap_address = int(self.profile.get("OS64", "vmmap_trap_address"), 16)
        self.heap_address = int(self.profile.get("OS64", "heap_address"), 16)
        self.heap_size = int(self.profile.get("OS64", "heap_size"), 16)        
        self.stack_address = stack_address
        self.stack_size = stack_size

        if self.ql.code:
            self.ql.mem.map(self.ql.os.entry_point, self.ql.os.code_ram_size, info="[shellcode_stack]")
            self.ql.os.entry_point  = (self.ql.os.entry_point + 0x200000 - 0x1000)
            
            self.ql.mem.write(self.entry_point, self.ql.code)

            self.ql.reg.arch_sp = self.ql.os.entry_point
            return
        
        self.ql.os.macho_task = MachoTask()
        self.ql.os.macho_fs = FileSystem(self.ql)
        self.ql.os.macho_mach_port = MachPort(2187)
        self.ql.os.macho_port_manager = MachPortManager(self.ql, self.ql.os.macho_mach_port)
        self.ql.os.macho_host_server = MachHostServer(self.ql)
        self.ql.os.macho_task_server = MachTaskServer(self.ql)
        
        self.envs = env_dict_to_array(self.env)
        self.apples = self.ql.os.path.transform_to_relative_path(self.ql.path)
        self.ql.os.heap = QlMemoryHeap(self.ql, self.heap_address, self.heap_address + self.heap_size)

        # FIXME: Not working due to overlarge mapping, need to fix it
        # vm_shared_region_enter(self.ql)

        map_commpage(self.ql)

        self.ql.os.thread_management = QlMachoThreadManagement(self.ql)
        self.ql.os.macho_thread = QlMachoThread(self.ql)
        self.ql.os.thread_management.cur_thread = self.ql.os.macho_thread
        self.ql.os.macho_vmmap_end = vmmap_trap_address
        self.stack_sp = stack_address + stack_size
        self.macho_file     = MachoParser(self.ql, self.ql.path)
        self.is_driver      = (self.macho_file.header.file_type == 0xb)
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
        if self.is_driver:
            self.loadDriver(self.stack_address)
            self.ql.hook_code(hook_kernel_api)
        else:
            self.loadMacho()
        self.stack_address = (int(self.stack_sp))
        self.ql.reg.arch_sp = self.stack_address # self.stack_sp
        self.init_sp = self.ql.reg.arch_sp
        self.ql.os.macho_task.min_offset = page_align_end(self.vm_end_addr, PAGE_SIZE)

    def loadDriver(self, stack_addr, loadbase = -1, argv = [], env = {}):
        self.import_symbols = {}
        PAGE_SIZE = 0x1000
        if loadbase < 0:
            loadbase = 0xffffff7000000000
        self.slide = loadbase
        self.load_address = loadbase
        cmds = self.macho_file.commands
        for cmd in cmds:
            if cmd.cmd_id == LC_SEGMENT_64:
                self.loadSegment64(cmd, False)

        self.kext_size = self.vm_end_addr - loadbase

        kernel_path = os.path.join(self.ql.rootfs, "System/Library/Kernels/kernel.development")
        self.ql.log.info("Parsing kernel:")
        self.kernel = MachoParser(self.ql, kernel_path)

        # Create memory for external static symbol jmp code
        self.static_addr = self.vm_end_addr
        self.static_size = PAGE_SIZE
        self.ql.mem.map(self.static_addr, self.static_size, info="[STATIC]")
        self.vm_end_addr += PAGE_SIZE
        self.ql.log.info("Memory for external static symbol is created at 0x%x with size 0x%x" % (self.static_addr, self.static_size))
        self.static_symbols = {}

        # Load kernel
        self.slide = 0
        self.loading_file = self.kernel
        kern_cmds = self.kernel.commands
        self.kernel_base = None
        for cmd in kern_cmds:
            if cmd.cmd_id == LC_SEGMENT_64:
                if self.kernel_base is None:
                    self.kernel_base = cmd.vm_address
                self.loadSegment64(cmd, False)

        self.ql.log.info("Kernel loaded at 0x%x" % self.kernel_base)

        # Resolve local relocation
        for relocation in self.macho_file.dysymbol_table.locreloc:
            seg = None
            for segment in self.macho_file.segments:
                if relocation.symbolnum in segment.sections_index:
                    seg = segment
                    break
            current_value, = struct.unpack("<Q", self.ql.mem.read(loadbase + relocation.address, 8))
            self.ql.log.debug("Patching relocation (0x%x): from 0x%x, update to segment %s at 0x%x" % (loadbase + relocation.address, current_value, seg.name, loadbase + seg.vm_address))
            self.ql.mem.write(loadbase + relocation.address, struct.pack("<Q", current_value + loadbase ))

        # Resolve dynamic symbols
        kernel_local_symbols_index = self.kernel.dysymbol_table.locsymbol_index
        kernel_local_symbols_num = self.kernel.dysymbol_table.locsymbol_num
        self.kernel_local_symbols_detail = self.kernel.symbol_table.details(kernel_local_symbols_index, kernel_local_symbols_num, self.kernel.string_table)

        for key in self.kernel_local_symbols_detail:
            value = self.kernel_local_symbols_detail[key]
            self.import_symbols[value["n_value"]] = key.decode('ascii')

        kernel_extrn_symbols_index = self.kernel.dysymbol_table.defext_index
        kernel_extrn_symbols_num = self.kernel.dysymbol_table.defext_num
        self.kernel_extrn_symbols_detail = self.kernel.symbol_table.details(kernel_extrn_symbols_index, kernel_extrn_symbols_num, self.kernel.string_table)

        for key in self.kernel_extrn_symbols_detail:
            value = self.kernel_extrn_symbols_detail[key]
            self.import_symbols[value["n_value"]] = key.decode('ascii')

        offset = 0
        """
        0:  48 83 ec 08             sub    rsp,0x8
        4:  c7 04 24 af be ad de    mov    DWORD PTR [rsp],0xdeadbeaf
        b:  c7 44 24 04 be ba fe    mov    DWORD PTR [rsp+0x4],0xcafebabe
        12: ca
        13: c3                      ret
        """

        for relocation in self.macho_file.dysymbol_table.extreloc:
            symbol = self.macho_file.symbol_table.symbols[relocation.symbolnum]
            symname = self.macho_file.string_table[symbol.n_strx]
            if relocation.length == 2 and relocation.rtype == 2:
                if symname not in self.static_symbols:
                    if symname in self.kernel_local_symbols_detail:
                        real_addr = self.kernel_local_symbols_detail[symname]["n_value"]
                    elif b"_" + symname in self.kernel_extrn_symbols_detail:
                        # ___MALLOC ftw???
                        real_addr = self.kernel_extrn_symbols_detail[b"_" + symname]["n_value"]
                    elif symname in self.kernel_extrn_symbols_detail:
                        real_addr = self.kernel_extrn_symbols_detail[symname]["n_value"]
                    else:
                        self.ql.log.info("Static symbol %s not found" % symname)
                        continue
                    self.import_symbols[real_addr] = symname.decode('ascii')
                    lo_addr = real_addr & 0xffffffff
                    hi_addr = (real_addr & 0xffffffff00000000) // 0x100000000
                    jmpcode = b"\x48\x83\xec\x08\xc7\x04\x24" + struct.pack("<I", lo_addr) + b"\xc7\x44\x24\x04" + struct.pack("<I", hi_addr) + b"\xc3"

                    self.ql.mem.write(self.static_addr + offset, jmpcode)

                    self.ql.mem.write(loadbase + relocation.address, struct.pack("<I", self.static_addr + offset - (loadbase + relocation.address + 4)))
                    self.static_symbols[symname] = self.static_addr + offset
                    offset += len(jmpcode)
                else:
                    self.ql.mem.write(loadbase + relocation.address, struct.pack("<I", self.static_symbols[symname] - (loadbase + relocation.address + 4)))

#                 ql.log.info("Patching relocation (0x%x): %s at 0x%x" % (loadbase + relocation.address, symname, self.static_symbols[symname]))
                continue
            if relocation.extern == 0 or relocation.length != 3:
                continue

            if symname in self.kernel_local_symbols_detail:
                # ql.log.debug("Patching relocation (0x%x): %s at 0x%x" % (loadbase + relocation.address, symname, self.kernel_local_symbols_detail[symname]["n_value"]))
                self.ql.mem.write(loadbase + relocation.address, struct.pack("<Q", self.kernel_local_symbols_detail[symname]["n_value"]))
            elif symname in self.kernel_extrn_symbols_detail:
                # ql.log.debug("Patching relocation (0x%x): %s at 0x%x" % (loadbase + relocation.address, symname, self.kernel_extrn_symbols_detail[symname]["n_value"]))
                self.ql.mem.write(loadbase + relocation.address, struct.pack("<Q", self.kernel_extrn_symbols_detail[symname]["n_value"]))
            else:
                self.ql.log.info("Symbol %s not found!" % symname)

        # Update resolved symbols in table
        self.loadbase = loadbase
        index = self.macho_file.dysymbol_table.locsymbol_index
        num = self.macho_file.dysymbol_table.locsymbol_num
        self.kext_local_symbols = self.macho_file.symbol_table.details(index, num, self.macho_file.string_table)

        index = self.macho_file.dysymbol_table.defext_index
        num = self.macho_file.dysymbol_table.defext_num
        self.kext_extern_symbols = self.macho_file.symbol_table.details(index, num, self.macho_file.string_table)

        if self.IOKit is True:
            # Get exported vtables
            self.vtables = {}
            for symbol in self.macho_file.symbol_table.symbols:
                if symbol.n_type == 0xf and "__const".ljust(16, "\x00") == self.macho_file.sections[symbol.n_sect].name:
                    symname = self.macho_file.string_table[symbol.n_strx]
                    self.ql.log.info("Found vtable of %s at 0x%x" % (symname, loadbase + symbol.n_value))
                    self.vtables[symname] = loadbase + symbol.n_value
     
            kext = self.plist["IOKitPersonalities"][self.kext_name]["IOClass"]
            user = self.plist["IOKitPersonalities"][self.kext_name]["IOUserClientClass"]

            self.kext_alloc = None
            self.kext_init = None
            self.kext_attach = None
            self.kext_probe = None
            self.kext_detach = None
            self.kext_start = None

            # No need to detach since we will emulate kext and user together
            self.user_alloc = None
            self.user_initWithTask = None
            self.user_attach = None
            self.user_start = None

            for relocation in self.macho_file.dysymbol_table.extreloc:
                symbol = self.macho_file.symbol_table.symbols[relocation.symbolnum]
                symname = self.macho_file.string_table[symbol.n_strx]
                if b"externalMethod" in symname:
                    current_value, = struct.unpack("<Q", self.ql.mem.read(loadbase + relocation.address, 8))
                    print(symname, hex(relocation.address), hex(current_value))

            for symname in self.vtables:
                # TODO: Use IDA Pro to dump offset of methods of IOService and IOUserClient objects
                if symname.decode().endswith(str(len(kext)) + kext + "9MetaClassE"):
                    self.kext_alloc, = struct.unpack("<Q", self.ql.mem.read(self.vtables[symname] + 0x98, 8))
                elif symname.decode().endswith(str(len(kext)) + kext):
                    self.kext_init, = struct.unpack("<Q", self.ql.mem.read(self.vtables[symname] + 0x258, 8))
                    self.kext_attach, = struct.unpack("<Q", self.ql.mem.read(self.vtables[symname] + 0x680, 8))
                    self.kext_probe, = struct.unpack("<Q", self.ql.mem.read(self.vtables[symname] + 0x5c8, 8))
                    self.kext_detach, = struct.unpack("<Q", self.ql.mem.read(self.vtables[symname] + 0x688, 8))
                    self.kext_start, = struct.unpack("<Q", self.ql.mem.read(self.vtables[symname] + 0x5d0, 8))
                elif symname.decode().endswith(str(len(user)) + user + "9MetaClassE"):
                    self.user_alloc, = struct.unpack("<Q", self.ql.mem.read(self.vtables[symname] + 0x98, 8))
                elif symname.decode().endswith(str(len(user)) + user):
                    self.user_initWithTask, = struct.unpack("<Q", self.ql.mem.read(self.vtables[symname] + 0x8f0, 8))
                    self.user_attach, = struct.unpack("<Q", self.ql.mem.read(self.vtables[symname] + 0x680, 8))
                    self.user_start, = struct.unpack("<Q", self.ql.mem.read(self.vtables[symname] + 0x5d0, 8))
                    self.user_externalMethod, = struct.unpack("<Q", self.ql.mem.read(self.vtables[symname] + 0x860, 8))
        else:
#             from pprint import pprint
#             pprint(kext_local_symbols)
            if b"__realmain" in self.kext_local_symbols:
                realmain = loadbase + self.kext_local_symbols[b"__realmain"]["n_value"]
                current_value, = struct.unpack("<Q", self.ql.mem.read(realmain, 8))
                self.ql.log.info("Found entry point: 0x%x" % (current_value))
                self.kext_start = current_value
            else:
                self.ql.log.info("Entry point not found")
                self.kext_start = None
            
            if b"__antimain" in self.kext_local_symbols:
                antimain = loadbase + self.kext_local_symbols[b"__antimain"]["n_value"]
                current_value, = struct.unpack("<Q", self.ql.mem.read(antimain, 8))
                self.ql.log.info("Found exit point: 0x%x" % (current_value))
                self.kext_stop = current_value
            else:
                self.ql.log.info("Exit point not found")
                self.kext_stop = None

            self.slide = loadbase 

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
                                raise QlErrorMACHOFormat("Error No Dyld path")
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
                self.ql.log.info("ProcEntry: {}".format(hex(self.proc_entry)))
                self.entry_point = self.proc_entry + self.dyld_slide
                self.ql.log.info("Dyld entry point: {}".format(hex(self.entry_point)))
            else:
                self.entry_point = self.proc_entry + self.slide
            self.ql.log.info("Binary Entry Point: 0x{:X}".format(self.binary_entry))
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

        if seg_size == 0:
            return -1

        if seg_name[:10] == "__PAGEZERO":
            self.ql.log.debug("Now loading {}, VM[{}:{}] for pagezero actually it only got a page size".format(seg_name, hex(vaddr_start), hex(vaddr_end)))
            self.ql.mem.map(vaddr_start, PAGE_SIZE, info="[__PAGEZERO]")
            self.ql.mem.write(vaddr_start, b'\x00' * PAGE_SIZE)
            if self.vm_end_addr < vaddr_end:
                self.vm_end_addr = vaddr_end
        else:
            if vaddr_end % PAGE_SIZE != 0:
                vaddr_end = ((vaddr_end // PAGE_SIZE) + 1) * PAGE_SIZE
                seg_size = vaddr_end - vaddr_start
                seg_data = seg_data.ljust(seg_size, b'\0')

            self.ql.log.debug("Now loading {}, VM[{}:{}]".format(seg_name, hex(vaddr_start), hex(vaddr_end)))
            self.ql.mem.map(vaddr_start, seg_size,  info="[loadSegment64]")
            self.ql.mem.write(vaddr_start, seg_data)
            if self.vm_end_addr < vaddr_end:
                self.vm_end_addr = vaddr_end

        return vaddr_start
    
    def loadUnixThread(self, cmd, isdyld):
        if not isdyld:
            self.binary_entry = cmd.entry
 
        self.proc_entry = cmd.entry
        self.ql.log.debug("Binary Thread Entry: {}".format(hex(cmd.entry)))


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
            self.ql.log.debug('add argvs ptr {}'.format(hex(ptr)))
            ptr += len(item) + 1
        
        for item in self.envs[::-1]:
            envs_ptr.append(ptr)
            self.ql.log.debug('add envs ptr {}'.format(hex(ptr)))
            ptr += len(item) + 1

        for item in self.apples[::-1]:
            apple_ptr.append(ptr)
            self.ql.log.debug('add apple ptr {}'.format(hex(ptr)))
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
            self.ql.log.debug("SP 0x%x, content 0x%x" % (self.stack_sp, item))
        argvs_ptr_ptr = ptr 

        self.push_stack_addr(self.argc)
        ptr -= 4
        self.ql.log.debug("SP 0x%x, content 0x%x" % (self.stack_sp, self.argc))
       
        if self.using_dyld:
            ptr -= 4
            #ql.log.info("Binary Dynamic Entry Point: {:X}".format(self.binary_entry))
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
        self.ql.log.debug("SP {} write data len {}".format(hex(self.stack_sp), length))
        
        return self.stack_sp
    
    def push_stack_addr(self, data):
        align = self.ptr_align
        
        if data == 0:
            content = b'\x00\x00\x00\x00\x00\x00\x00\x00'
        else:
            content = struct.pack('<Q', data)

        if len(content) != align:
            self.ql.log.info('stack align error')
            return 
        
        self.stack_sp -= align
        self.ql.mem.write(self.stack_sp, content)

        return self.stack_sp
