#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import ctypes, types, struct, ast
from contextlib import contextmanager

from unicorn import *
from unicorn.x86_const import *

from qiling.arch.x86_const import *
from qiling.os.utils import *
from qiling.const import *
from qiling.os.memory import QlMemoryHeap
from qiling.os.uefi.utils import *
from qiling.os.uefi.type64 import *
from qiling.os.uefi.fncc import *
from qiling.os.uefi.bootup import *
from qiling.os.uefi.runtime import *

from qiling.os.windows.fncc import *

import pefile
from .loader import QlLoader

class QlLoaderPE_UEFI(QlLoader):
    def __init__(self, ql):
        super(QlLoaderPE_UEFI, self).__init__(ql)
        self.ql = ql
        self.modules = []
        self.events = {}
        self.handle_dict = {}
        self.notify_list = []

    @contextmanager
    def map_memory(self, addr, size):
        self.ql.mem.map(addr, size)
        try:
            yield
        finally:
            self.ql.mem.unmap(addr, size)


    def install_loaded_image_protocol(self, image_base, image_size, entry_point):
        loaded_image_protocol = EFI_LOADED_IMAGE_PROTOCOL()
        loaded_image_protocol.Revision = int(self.ql.os.profile["LOADED_IMAGE_PROTOCOL"]["revision"], 16)
        loaded_image_protocol.ParentHandle = 0
        loaded_image_protocol.SystemTable = self.system_table_ptr
        loaded_image_protocol.DeviceHandle = image_base
        loaded_image_protocol.FilePath = 0 # This is a handle to a complex path object, skip it for now.
        loaded_image_protocol.LoadOptionsSize = 0
        loaded_image_protocol.LoadOptions = 0
        loaded_image_protocol.ImageBase = image_base
        loaded_image_protocol.ImageSize = image_size
        loaded_image_protocol.ImageCodeType = EfiLoaderCode
        loaded_image_protocol.ImageDataType = EfiLoaderData
        loaded_image_protocol.Unload = 0

        loaded_image_protocol_ptr = self.heap.alloc(ctypes.sizeof(EFI_LOADED_IMAGE_PROTOCOL))
        self.ql.mem.write(loaded_image_protocol_ptr, convert_struct_to_bytes(loaded_image_protocol))
        self.handle_dict[image_base] = {self.loaded_image_protocol_guid: loaded_image_protocol_ptr}
        self.loaded_image_protocol_modules.append(image_base)


    def map_and_load(self, path):
        pe = pefile.PE(path, fast_load=True)
        
        IMAGE_BASE = pe.OPTIONAL_HEADER.ImageBase
        IMAGE_SIZE = self.ql.mem.align(pe.OPTIONAL_HEADER.SizeOfImage, 0x1000)

        while IMAGE_BASE + IMAGE_SIZE < self.heap_base_address:
            if not self.ql.mem.is_mapped(IMAGE_BASE, 1):
                self.ql.mem.map(IMAGE_BASE, IMAGE_SIZE)
                pe.parse_data_directories()
                data = bytearray(pe.get_memory_mapped_image())
                self.ql.mem.write(IMAGE_BASE, bytes(data))
                self.ql.nprint("[+] Loading %s to 0x%x" % (path, IMAGE_BASE))
                entry_point = IMAGE_BASE + pe.OPTIONAL_HEADER.AddressOfEntryPoint
                if self.entry_point == 0:
                    # Setting entry point to the first loaded module entry point, so the debugger can break.
                    self.entry_point = entry_point
                self.ql.nprint("[+] PE entry point at 0x%x" % entry_point)
                self.install_loaded_image_protocol(IMAGE_BASE, IMAGE_SIZE, entry_point)
                self.modules.append((path, IMAGE_BASE, entry_point, pe))
                self.images.append(self.coverage_image(IMAGE_BASE, IMAGE_BASE + pe.NT_HEADERS.OPTIONAL_HEADER.SizeOfImage, path))
                return True
            else:
                IMAGE_BASE += 0x10000
                pe.relocate_image(IMAGE_BASE)
        return False

    def unload_modules(self):
        for handle in self.loaded_image_protocol_modules:
            dic = self.handle_dict[handle]
            buf = bytes(self.ql.mem.read(dic[self.loaded_image_protocol_guid], ctypes.sizeof(EFI_LOADED_IMAGE_PROTOCOL)))
            buffer = ctypes.create_string_buffer(buf)
            loaded_image_protocol = EFI_LOADED_IMAGE_PROTOCOL()
            ctypes.memmove(ctypes.addressof(loaded_image_protocol), buffer, ctypes.sizeof(loaded_image_protocol))
            unload_ptr = struct.unpack("Q", loaded_image_protocol.Unload)[0]
            if unload_ptr != 0:
                self.ql.stack_push(self.end_of_execution_ptr)
                self.ql.reg.rcx = handle
                self.ql.reg.rip = unload_ptr
                self.ql.nprint(f'[+] Unloading module 0x{handle:x}, calling 0x{unload_ptr:x}')
                self.loaded_image_protocol_modules.remove(handle)
                return True
        return False

    def execute_next_module(self):
        path, image_base, entry_point, pe = self.modules.pop(0)
        self.ql.stack_push(self.end_of_execution_ptr)
        self.ql.reg.rcx = image_base
        self.ql.reg.rdx = self.system_table_ptr
        self.ql.reg.rip = entry_point
        self.ql.os.entry_point = entry_point
        self.ql.nprint(f'[+] Running from 0x{self.entry_point:x} of {path}')


    def run(self):
        self.loaded_image_protocol_guid = self.ql.os.profile["LOADED_IMAGE_PROTOCOL"]["guid"]
        self.loaded_image_protocol_modules = []
        self.tpl = 4 # TPL_APPLICATION
        self.user_defined_api = self.ql.os.user_defined_api
        self.user_defined_api_onenter = self.ql.os.user_defined_api_onenter
        self.user_defined_api_onexit = self.ql.os.user_defined_api_onexit
        
        if self.ql.archtype == QL_ARCH.X8664:
            self.heap_base_address = int(self.ql.os.profile.get("OS64", "heap_address"), 16)
            self.heap_base_size = int(self.ql.os.profile.get("OS64", "heap_size"), 16)       
        elif self.ql.archtype == QL_ARCH.X86:
            self.heap_base_address = int(self.ql.os.profile.get("OS32", "heap_address"), 16)
            self.heap_base_size = int(self.ql.os.profile.get("OS32", "heap_size"), 16)
        
        self.heap = QlMemoryHeap(self.ql, self.heap_base_address, self.heap_base_address + self.heap_base_size)
        self.entry_point = 0
        self.load_address = 0  

        if self.ql.archtype == QL_ARCH.X8664:
            self.stack_address = int(self.ql.os.profile.get("OS64", "stack_address"), 16)
            self.stack_size = int(self.ql.os.profile.get("OS64", "stack_size"), 16)
            
        elif self.ql.archtype == QL_ARCH.X86:        
            self.stack_address = int(self.ql.os.profile.get("OS32", "stack_address"), 16)
            self.stack_size = int(self.ql.os.profile.get("OS32", "stack_size"), 16)     

        # set stack pointer
        self.ql.nprint("[+] Initiate stack address at 0x%x" % self.stack_address)
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

        # set SystemTable to image base for now
        pointer_size = ctypes.sizeof(ctypes.c_void_p)
        system_table_heap_size = 1024 * 1024
        system_table_heap = self.heap.alloc(system_table_heap_size)
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
        efi_configuration_table.VendorGuid.Data1 = int(self.ql.os.profile.get("GUID", "data1"), 16)
        efi_configuration_table.VendorGuid.Data2 = int(self.ql.os.profile.get("GUID", "data2"), 16)
        efi_configuration_table.VendorGuid.Data3 = int(self.ql.os.profile.get("GUID", "data3"), 16)
        
        data4 = ast.literal_eval(self.ql.os.profile.get("GUID", "data4"))
        datalist = 0
        for data4_list in data4:
            efi_configuration_table.VendorGuid.Data4[datalist] = data4_list
            datalist += 1  
        
        efi_configuration_table.VendorTable = self.ql.os.profile.getint("GUID", "vendortable")
        self.efi_configuration_table = [self.ql.os.profile["GUID"]["configuration_table"]]
        self.ql.mem.write(runtime_services_ptr, convert_struct_to_bytes(runtime_services))
        self.ql.mem.write(boot_services_ptr, convert_struct_to_bytes(boot_services))
        self.ql.mem.write(self.efi_configuration_table_ptr, convert_struct_to_bytes(efi_configuration_table))
        self.ql.mem.write(self.system_table_ptr, convert_struct_to_bytes(system_table))

        # Make sure no module will occupy the NULL page
        with self.map_memory(0, 0x1000):
            if len(self.ql.argv) > 1:
                for dependency in self.ql.argv[1:]:
                    if not self.map_and_load(dependency):
                        raise QlErrorFileType("Can't map dependency")

            # Load main module
            self.map_and_load(self.ql.path)
            self.ql.nprint("[+] Done with loading %s" % self.ql.path)

        #return address
        self.end_of_execution_ptr = system_table_heap_ptr
        self.ql.mem.write(self.end_of_execution_ptr, b'\xcc')
        system_table_heap_ptr += pointer_size
        self.ql.hook_address(hook_EndOfExecution, self.end_of_execution_ptr)
        self.notify_ptr = system_table_heap_ptr
        system_table_heap_ptr += pointer_size

        self.execute_next_module()
