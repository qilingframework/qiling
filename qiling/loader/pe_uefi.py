#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import ctypes
import types
import struct
from unicorn import *
from unicorn.x86_const import *
from qiling.arch.x86_const import *
from qiling.os.utils import *
from qiling.const import *
from qiling.os.memory import QlMemoryHeap
from qiling.os.uefi.utils import *
from qiling.os.uefi.uefi_types_64 import *
from qiling.os.uefi.fncc import *
from qiling.os.uefi.boot_services_hooks import *
from qiling.os.uefi.runtime_services_hooks import *

from qiling.os.windows.fncc import *
from qiling.os.windows.fncc import _get_param_by_index

import pefile
from .loader import QlLoader

class QlLoaderPE_UEFI(QlLoader):
    def __init__(self, ql):
        super()
        self.ql = ql
    
    def run(self):
        self.profile = self.ql.profile
        self.tpl = 4 # TPL_APPLICATION
        self.hook_override = {}
        self.modules = []
        self.events = {}
        self.handle_dict = {}
        self.notify_list = []
        self.notify_immediately = False
        if self.ql.archtype == QL_ARCH.X8664:
            self.heap_base_address = int(self.profile.get("OS64", "heap_address"),16)
            self.heap_base_size = int(self.profile.get("OS64", "heap_size"),16)       
        elif self.ql.archtype == QL_ARCH.X86:
            self.heap_base_address = int(self.profile.get("OS32", "heap_address"),16)
            self.heap_base_size = int(self.profile.get("OS32", "heap_size"),16)
        self.heap = QlMemoryHeap(self.ql, self.heap_base_address, self.heap_base_address + self.heap_base_size)
        self.entry_point = 0
        self.load_address = 0  
        self.load()

    def map_and_load(self, path):
        pe = pefile.PE(path, fast_load=True)
        
        IMAGE_BASE = pe.OPTIONAL_HEADER.ImageBase
        IMAGE_SIZE = self.heap._align(pe.OPTIONAL_HEADER.SizeOfImage, 0x1000)

        while IMAGE_BASE + IMAGE_SIZE < self.heap_base_address:
            try:
                self.ql.mem.map(IMAGE_BASE, IMAGE_SIZE)
                pe.parse_data_directories()
                data = bytearray(pe.get_memory_mapped_image())
                self.ql.mem.write(IMAGE_BASE, bytes(data))
                self.ql.nprint("[+] Loading %s to 0x%x" % (path, IMAGE_BASE))
                entry_point = IMAGE_BASE + pe.OPTIONAL_HEADER.AddressOfEntryPoint
                if self.entry_point == 0:
                    # Setting entrypoint to the first loaded module entrypoint, so the debugger can break.
                    self.entry_point = entry_point
                self.ql.nprint("[+] PE entry point at 0x%x" % entry_point)
                self.modules.append((path, entry_point, pe))
                return True
            except UcError as e:
                if e.errno == UC_ERR_MAP:
                    IMAGE_BASE += 0x10000
                    pe.relocate_image(IMAGE_BASE)
                else:
                    raise
            except QlMemoryMappedError:
                IMAGE_BASE += 0x10000
                pe.relocate_image(IMAGE_BASE)
        return False

    def load(self):

        """
        initiate UC needs to be in loader, or else it will kill execve
        Note: This is EFI, but for the sake of same with others OS
        """
        self.ql.uc = self.ql.arch.init_uc

        if self.ql.archtype == QL_ARCH.X8664:
            self.stack_address = int(self.profile.get("OS64", "stack_address"),16)
            self.stack_size = int(self.profile.get("OS64", "stack_size"),16)
            
        elif self.ql.archtype == QL_ARCH.X86:        
            self.stack_address = int(self.profile.get("OS32", "stack_address"),16)
            self.stack_size = int(self.profile.get("OS32", "stack_size"),16)     

        if self.ql.path and not self.ql.shellcoder:
            
            # set stack pointer
            self.ql.nprint("[+] Initiate stack address at 0x%x " % self.stack_address)
            self.ql.mem.map(self.stack_address, self.stack_size)

            # Stack should not init at the very bottom. Will cause errors with Dlls
            sp = self.stack_address + self.stack_size - 0x1000

            if self.ql.archtype== QL_ARCH.X86:
                raise QlErrorArch("[!] Only 64 bit arch supported for now.")

            elif self.ql.archtype== QL_ARCH.X8664:
                self.ql.reg.rsp = sp
                self.ql.reg.rbp = sp

            else:
                raise QlErrorArch("[!] Unknown ql.arch")

            if len(self.ql.argv) > 1:
                for dependency in self.ql.argv[1:]:
                    if not self.map_and_load(dependency):
                        raise QlErrorFileType("Can't map dependency")

            # Load main module
            self.map_and_load(self.ql.path)

            self.ql.nprint("[+] Done with loading %s" % self.ql.path)
            self.filepath = b"D:\\" + bytes(self.ql.path.replace("/", "\\"), "utf-8")

        elif self.ql.shellcoder:
            # setup stack memory
            self.ql.mem.map(self.ql.stack_address, self.ql.stack_size)
            self.ql.reg.rsp =  self.ql.stack_address + 0x3000
            self.ql.reg.rsp = self.ql.stack_address + 0x3000
            # load shellcode in
            self.ql.mem.map(self.ql.code_address, self.ql.code_size)
            self.ql.mem.write(self.ql.code_address, self.ql.shellcoder)
        
        # set SystemTable to image base for now
        pointer_size = ctypes.sizeof(ctypes.c_void_p)
        system_table_heap_size = 1024*1024
        system_table_heap = self.heap.mem_alloc(system_table_heap_size)
        self.ql.mem.write(system_table_heap, b'\x90'*system_table_heap_size)
        self.system_table_ptr = system_table_heap
        system_table = EFI_SYSTEM_TABLE()
        system_table_heap_ptr = system_table_heap + ctypes.sizeof(EFI_SYSTEM_TABLE)
        
        runtime_services_ptr = system_table_heap_ptr
        system_table.RuntimeServices = runtime_services_ptr
        system_table_heap_ptr += ctypes.sizeof(EFI_RUNTIME_SERVICES)
        system_table_heap_ptr, runtime_services = hook_EFI_RUNTIME_SERVICES(self.ql, system_table_heap_ptr)

        boot_services_ptr = system_table_heap_ptr
        system_table.BootServices = boot_services_ptr
        system_table_heap_ptr += ctypes.sizeof(EFI_BOOT_SERVICES)
        system_table_heap_ptr, boot_services = hook_EFI_BOOT_SERVICES(self.ql, system_table_heap_ptr)

        self.efi_configuration_table_ptr = system_table_heap_ptr
        system_table.ConfigurationTable = self.efi_configuration_table_ptr
        system_table.NumberOfTableEntries = 1
        system_table_heap_ptr += ctypes.sizeof(EFI_CONFIGURATION_TABLE) * 100 # We don't expect more then a few entries.
        efi_configuration_table = EFI_CONFIGURATION_TABLE()

        #   0x7739f24c, 0x93d7, 0x11d4, {0x9a, 0x3a, 0x0, 0x90, 0x27, 0x3f, 0xc1, 0x4d } \
        efi_configuration_table.VendorGuid.Data1 = 0x7739f24c
        efi_configuration_table.VendorGuid.Data2 = 0x93d7
        efi_configuration_table.VendorGuid.Data3 = 0x11d4
        efi_configuration_table.VendorGuid.Data4[0] = 0x9a
        efi_configuration_table.VendorGuid.Data4[1] = 0x3a
        efi_configuration_table.VendorGuid.Data4[2] = 0
        efi_configuration_table.VendorGuid.Data4[3] = 0x90
        efi_configuration_table.VendorGuid.Data4[4] = 0x27
        efi_configuration_table.VendorGuid.Data4[5] = 0x3f
        efi_configuration_table.VendorGuid.Data4[6] = 0xc1
        efi_configuration_table.VendorGuid.Data4[7] = 0x4d
        efi_configuration_table.VendorTable = 0
        self.efi_configuration_table = ['7739f24c-93d7-11d4-9a3a-0090273fc14d']

        self.ql.mem.write(runtime_services_ptr, convert_struct_to_bytes(runtime_services))
        self.ql.mem.write(boot_services_ptr, convert_struct_to_bytes(boot_services))
        self.ql.mem.write(self.efi_configuration_table_ptr, convert_struct_to_bytes(efi_configuration_table))
        self.ql.mem.write(self.system_table_ptr, convert_struct_to_bytes(system_table))

        #return address
        self.end_of_execution_ptr = system_table_heap_ptr
        self.ql.mem.write(self.end_of_execution_ptr, b'\xcc')
        system_table_heap_ptr += pointer_size
        self.ql.hook_address(hook_EndOfExecution, self.end_of_execution_ptr)
        self.notify_ptr = system_table_heap_ptr
        system_table_heap_ptr += pointer_size