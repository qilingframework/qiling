#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import ctypes, types, struct, ast, logging
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
from qiling.os.uefi.dxe_service import *
from qiling.os.uefi.smm_base2_protocol import *
from qiling.os.uefi.mm_access_protocol import *
from qiling.os.uefi.smm_sw_dispatch2_protocol import *

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
        self.next_image_base = 0x10000

    def save(self):
        saved_state = super(QlLoaderPE_UEFI, self).save()
        
        # We can't serialize self.modules since it contain pefile objects. let's remove it now and generate it again when loading.
        modules = []
        for mod in self.modules:
            modules.append(mod[:3])
        saved_state['modules'] = modules

        saved_state['events'] = self.events
        saved_state['handle_dict'] = self.handle_dict
        saved_state['notify_list'] = self.notify_list
        saved_state['next_image_base'] = self.next_image_base
        saved_state['loaded_image_protocol_modules'] = self.loaded_image_protocol_modules
        saved_state['tpl'] = self.tpl
        saved_state['efi_configuration_table'] = self.efi_configuration_table
        # since this class initialize the heap (that is hosted by the OS object), we will store it here.
        saved_state['heap'] = self.ql.os.heap.save()
        return saved_state

    def restore(self, saved_state):
        super(QlLoaderPE_UEFI, self).restore(saved_state)
        self.modules = []
        for mod in saved_state['modules']:
            self.modules.append(mod+(pefile.PE(mod[0], fast_load=True),))
        self.events = saved_state['events']
        self.handle_dict = saved_state['handle_dict']
        self.notify_list = saved_state['notify_list']
        self.next_image_base = saved_state['next_image_base']
        self.loaded_image_protocol_modules = saved_state['loaded_image_protocol_modules']
        self.tpl = saved_state['tpl']
        self.efi_configuration_table = saved_state['efi_configuration_table']
        self.ql.os.heap.restore(saved_state['heap'])

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

        loaded_image_protocol_ptr = self.ql.os.heap.alloc(ctypes.sizeof(EFI_LOADED_IMAGE_PROTOCOL))
        self.ql.mem.write(loaded_image_protocol_ptr, convert_struct_to_bytes(loaded_image_protocol))
        self.handle_dict[image_base] = {self.loaded_image_protocol_guid: loaded_image_protocol_ptr}
        self.loaded_image_protocol_modules.append(image_base)


    def map_and_load(self, path, execute_now=False):
        ql = self.ql
        pe = pefile.PE(path, fast_load=True)

        # Make sure no module will occupy the NULL page
        if self.next_image_base > pe.OPTIONAL_HEADER.ImageBase:
            IMAGE_BASE = self.next_image_base
            pe.relocate_image(IMAGE_BASE)
        else:
            IMAGE_BASE = pe.OPTIONAL_HEADER.ImageBase
        IMAGE_SIZE = ql.mem.align(pe.OPTIONAL_HEADER.SizeOfImage, 0x1000)

        while IMAGE_BASE + IMAGE_SIZE < self.heap_base_address:
            if not ql.mem.is_mapped(IMAGE_BASE, 1):
                self.next_image_base = IMAGE_BASE + 0x10000
                ql.mem.map(IMAGE_BASE, IMAGE_SIZE)
                pe.parse_data_directories()
                data = bytearray(pe.get_memory_mapped_image())
                ql.mem.write(IMAGE_BASE, bytes(data))
                logging.info("[+] Loading %s to 0x%x" % (path, IMAGE_BASE))
                entry_point = IMAGE_BASE + pe.OPTIONAL_HEADER.AddressOfEntryPoint
                if self.entry_point == 0:
                    # Setting entry point to the first loaded module entry point, so the debugger can break.
                    self.entry_point = entry_point
                logging.info("[+] PE entry point at 0x%x" % entry_point)
                self.install_loaded_image_protocol(IMAGE_BASE, IMAGE_SIZE, entry_point)
                self.images.append(self.coverage_image(IMAGE_BASE, IMAGE_BASE + pe.NT_HEADERS.OPTIONAL_HEADER.SizeOfImage, path))
                if execute_now:
                    logging.info(f'[+] Running from 0x{entry_point:x} of {path}')
                    assembler = self.ql.create_assembler()
                    code = f"""
                        mov rcx, {IMAGE_BASE}
                        mov rdx, {self.system_table_ptr}
                        mov rax, {entry_point}
                        call rax
                    """
                    runcode, _ = assembler.asm(code)
                    ptr = ql.os.heap.alloc(len(runcode))
                    ql.mem.write(ptr, bytes(runcode))
                    ql.os.exec_arbitrary(ptr, ptr+len(runcode))

                else:
                    self.modules.append((path, IMAGE_BASE, entry_point, pe))
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
                logging.info(f'[+] Unloading module 0x{handle:x}, calling 0x{unload_ptr:x}')
                self.loaded_image_protocol_modules.remove(handle)
                return True
        return False

    def execute_module(self, path, image_base, entry_point, EOE_ptr):
        self.ql.stack_push(EOE_ptr)
        self.ql.reg.rcx = image_base
        self.ql.reg.rdx = self.system_table_ptr
        self.ql.reg.rip = entry_point
        self.ql.os.entry_point = entry_point
        logging.info(f'[+] Running from 0x{entry_point:x} of {path}')

    def execute_next_module(self):
        if self.ql.os.notify_before_module_execution(self.ql, self.modules[0][0]):
            return
        path, image_base, entry_point, pe = self.modules.pop(0)
        self.execute_module(path, image_base, entry_point, self.end_of_execution_ptr)


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
        
        self.ql.os.heap = QlMemoryHeap(self.ql, self.heap_base_address, self.heap_base_address + self.heap_base_size)
        self.entry_point = 0
        self.load_address = 0  

        if self.ql.archtype == QL_ARCH.X8664:
            self.stack_address = int(self.ql.os.profile.get("OS64", "stack_address"), 16)
            self.stack_size = int(self.ql.os.profile.get("OS64", "stack_size"), 16)
            
        elif self.ql.archtype == QL_ARCH.X86:        
            self.stack_address = int(self.ql.os.profile.get("OS32", "stack_address"), 16)
            self.stack_size = int(self.ql.os.profile.get("OS32", "stack_size"), 16)     

        # set stack pointer
        logging.info("[+] Initiate stack address at 0x%x" % self.stack_address)
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
        system_table_heap = self.ql.os.heap.alloc(system_table_heap_size)
        self.ql.mem.write(system_table_heap, b'\x90'*system_table_heap_size)
        self.system_table_ptr = system_table_heap
        system_table = EFI_SYSTEM_TABLE()
        system_table_heap_ptr = system_table_heap + ctypes.sizeof(EFI_SYSTEM_TABLE)
        
        self.runtime_services_ptr = system_table_heap_ptr
        system_table.RuntimeServices = self.runtime_services_ptr
        system_table_heap_ptr += ctypes.sizeof(EFI_RUNTIME_SERVICES)
        system_table_heap_ptr, self.runtime_services = hook_EFI_RUNTIME_SERVICES(self.ql, system_table_heap_ptr)
        self.runtime_services_end_ptr = system_table_heap_ptr - pointer_size

        self.boot_services_ptr = system_table_heap_ptr
        system_table.BootServices = self.boot_services_ptr
        system_table_heap_ptr += ctypes.sizeof(EFI_BOOT_SERVICES)
        system_table_heap_ptr, boot_services = hook_EFI_BOOT_SERVICES(self.ql, system_table_heap_ptr)
        self.boot_services_end_ptr = system_table_heap_ptr - pointer_size

        self.efi_configuration_table_ptr = system_table_heap_ptr
        system_table.ConfigurationTable = self.efi_configuration_table_ptr
        system_table.NumberOfTableEntries = 2
        system_table_heap_ptr += ctypes.sizeof(EFI_CONFIGURATION_TABLE) * 100 # We don't expect more then a few entries.
        efi_configuration_table = EFI_CONFIGURATION_TABLE()

        #   0x7739f24c, 0x93d7, 0x11d4, {0x9a, 0x3a, 0x0, 0x90, 0x27, 0x3f, 0xc1, 0x4d } \
        efi_configuration_table.VendorGuid.Data1 = int(self.ql.os.profile.get("HOB_LIST", "data1"), 16)
        efi_configuration_table.VendorGuid.Data2 = int(self.ql.os.profile.get("HOB_LIST", "data2"), 16)
        efi_configuration_table.VendorGuid.Data3 = int(self.ql.os.profile.get("HOB_LIST", "data3"), 16)
        
        data4 = ast.literal_eval(self.ql.os.profile.get("HOB_LIST", "data4"))
        datalist = 0
        for data4_list in data4:
            efi_configuration_table.VendorGuid.Data4[datalist] = data4_list
            datalist += 1  
        
        VendorTable_ptr = system_table_heap_ptr
        write_int64(self.ql, VendorTable_ptr, int(self.ql.os.profile.get("HOB_LIST", "vendortable"),16))
        system_table_heap_ptr += pointer_size
        efi_configuration_table.VendorTable = VendorTable_ptr
        self.efi_configuration_table = [self.ql.os.profile["HOB_LIST"]["guid"]]
        self.ql.mem.write(self.efi_configuration_table_ptr, convert_struct_to_bytes(efi_configuration_table))

        self.mm_system_table_ptr = system_table_heap_ptr
        system_table_heap_ptr += ctypes.sizeof(EFI_MM_SYSTEM_TABLE)
        system_table_heap_ptr, efi_mm_system_table = create_EFI_MM_SYSTEM_TABLE(self.ql, system_table_heap_ptr)
        self.mm_system_table_end_ptr = system_table_heap_ptr - pointer_size
        efi_mm_system_table.MmConfigurationTable = self.efi_configuration_table_ptr

        self.smm_base2_protocol_ptr = system_table_heap_ptr
        system_table_heap_ptr += ctypes.sizeof(EFI_SMM_BASE2_PROTOCOL)
        system_table_heap_ptr, smm_base2_protocol, efi_mm_system_table = install_EFI_SMM_BASE2_PROTOCOL(self.ql, system_table_heap_ptr, efi_mm_system_table)
        self.handle_dict[1] = {self.ql.os.profile.get("EFI_SMM_BASE2_PROTOCOL", "guid"): self.smm_base2_protocol_ptr}

        self.mm_access_protocol_ptr = system_table_heap_ptr
        system_table_heap_ptr += ctypes.sizeof(EFI_MM_ACCESS_PROTOCOL)
        system_table_heap_ptr, mm_access_protocol = install_EFI_MM_ACCESS_PROTOCOL(self.ql, system_table_heap_ptr)
        self.handle_dict[1][self.ql.os.profile.get("EFI_MM_ACCESS_PROTOCOL", "guid")] = self.mm_access_protocol_ptr

        self.smm_sw_dispatch2_protocol_ptr = system_table_heap_ptr
        system_table_heap_ptr += ctypes.sizeof(EFI_SMM_SW_DISPATCH2_PROTOCOL)
        system_table_heap_ptr, smm_sw_dispatch2_protocol = install_EFI_SMM_SW_DISPATCH2_PROTOCOL(self.ql, system_table_heap_ptr)
        self.handle_dict[1][self.ql.os.profile.get("EFI_SMM_SW_DISPATCH2_PROTOCOL", "guid")] = self.smm_sw_dispatch2_protocol_ptr

        self.dxe_services_ptr = system_table_heap_ptr
        system_table_heap_ptr += ctypes.sizeof(EFI_DXE_SERVICES)
        system_table_heap_ptr, dxe_services = install_EFI_DXE_SERVICES(self.ql, system_table_heap_ptr)
        efi_configuration_table = EFI_CONFIGURATION_TABLE()
        efi_configuration_table.VendorGuid.Data1 = int(self.ql.os.profile.get("DXE_SERVICE_TABLE", "data1"), 16)
        efi_configuration_table.VendorGuid.Data2 = int(self.ql.os.profile.get("DXE_SERVICE_TABLE", "data2"), 16)
        efi_configuration_table.VendorGuid.Data3 = int(self.ql.os.profile.get("DXE_SERVICE_TABLE", "data3"), 16)
        
        data4 = ast.literal_eval(self.ql.os.profile.get("DXE_SERVICE_TABLE", "data4"))
        datalist = 0
        for data4_list in data4:
            efi_configuration_table.VendorGuid.Data4[datalist] = data4_list
            datalist += 1  
       
        efi_configuration_table.VendorTable = self.dxe_services_ptr
        self.ql.mem.write(self.efi_configuration_table_ptr + ctypes.sizeof(EFI_CONFIGURATION_TABLE), convert_struct_to_bytes(efi_configuration_table))
        self.efi_configuration_table.append(self.ql.os.profile.get("DXE_SERVICE_TABLE", "guid"))
        

        self.ql.mem.write(self.runtime_services_ptr, convert_struct_to_bytes(self.runtime_services))
        self.ql.mem.write(self.boot_services_ptr, convert_struct_to_bytes(boot_services))
        self.ql.mem.write(self.system_table_ptr, convert_struct_to_bytes(system_table))
        self.ql.mem.write(self.mm_system_table_ptr, convert_struct_to_bytes(efi_mm_system_table))
        self.ql.mem.write(self.smm_base2_protocol_ptr, convert_struct_to_bytes(smm_base2_protocol))
        self.ql.mem.write(self.mm_access_protocol_ptr, convert_struct_to_bytes(mm_access_protocol))
        self.ql.mem.write(self.smm_sw_dispatch2_protocol_ptr, convert_struct_to_bytes(smm_sw_dispatch2_protocol))
        self.ql.mem.write(self.dxe_services_ptr, convert_struct_to_bytes(dxe_services))

        for dependency in self.ql.argv:
            if not self.map_and_load(dependency):
                raise QlErrorFileType("Can't map dependency")

        logging.info("[+] Done with loading %s" % self.ql.path)

        #return address
        self.end_of_execution_ptr = system_table_heap_ptr
        self.ql.mem.write(self.end_of_execution_ptr, b'\xcc')
        system_table_heap_ptr += pointer_size
        self.ql.hook_address(hook_EndOfExecution, self.end_of_execution_ptr)

        self.execute_next_module()

    def restore_runtime_services(self):
        self.ql.mem.write(self.runtime_services_ptr, convert_struct_to_bytes(self.runtime_services))

