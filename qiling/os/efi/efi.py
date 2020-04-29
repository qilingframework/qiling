#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import types
import struct
from unicorn import *
from unicorn.x86_const import *
from qiling.arch.x86_const import *
from qiling.os.utils import *
from qiling.const import *
from qiling.os.os import QlOs
from qiling.os.memory import Heap
from qiling.os.efi.efi_types_64 import *
from qiling.os.efi.fncc import *
from qiling.os.efi.boot_services_hooks import *
from qiling.os.efi.runtime_services_hooks import *

from qiling.os.windows.fncc import *
from qiling.os.windows.fncc import _get_param_by_index

import pefile

def hook_EndOfExecution(ql):
    if len(ql.modules) < 1:
        print(f'No more modules to run')
        ql.uc.emu_stop()
    else:
        path, entry_point, pe = ql.modules.pop(0)
        ql.stack_push(ql.end_of_execution_ptr)
        ql.register(UC_X86_REG_RDX, ql.system_table_ptr)
        print(f'Running {path} module entrypoint: 0x{entry_point:x}')
        ql.register(UC_X86_REG_RIP, entry_point)



class QlOsEfi(QlOs):
    def __init__(self, ql):
        super(QlOsEfi, self).__init__(ql)
        self.ql = ql
        self.ql.tpl = 4 # TPL_APPLICATION
        self.ql.modules = []
        self.ql.events = {}
        self.ql.handle_dict = {}
        self.ql.var_store = {}
        self.ql.elf_entry = 0 # We don't use elf, but gdbserver breaks if it's missing
        self.HEAP_BASE_ADDR = 0x500000000
        self.HEAP_SIZE = 0x5000000
        self.ql.heap = Heap(self.ql, self.HEAP_BASE_ADDR, self.HEAP_BASE_ADDR + self.HEAP_SIZE)
        self.load()

    def map_and_load(self, path):
        pe = pefile.PE(path, fast_load=True)
        
        IMAGE_BASE = pe.OPTIONAL_HEADER.ImageBase
        IMAGE_SIZE = self.ql.heap._align(pe.OPTIONAL_HEADER.SizeOfImage, 0x1000)

        while IMAGE_BASE + IMAGE_SIZE < self.HEAP_BASE_ADDR:
            try:
                self.ql.mem.map(IMAGE_BASE, IMAGE_SIZE)
                pe.parse_data_directories()
                data = bytearray(pe.get_memory_mapped_image())
                self.ql.mem.write(IMAGE_BASE, bytes(data))
                self.ql.nprint("[+] Loading %s to 0x%x" % (path, IMAGE_BASE))
                entry_point = IMAGE_BASE + pe.OPTIONAL_HEADER.AddressOfEntryPoint
                if self.ql.entry_point == 0:
                    # Setting entrypoint to the first loaded module entrypoint, so the debugger can break.
                    self.ql.entry_point = entry_point
                self.ql.nprint("[+] PE entry point at 0x%x" % entry_point)
                self.ql.modules.append((path, entry_point, pe))
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

        if self.ql.archtype== QL_X8664:
            self.QL_EFI_STACK_ADDRESS = 0x7ffffffde000
            self.QL_EFI_STACK_SIZE = 0x40000
            
        elif self.ql.archtype== QL_X86:        
            self.QL_EFI_STACK_ADDRESS = 0xfffdd000
            self.QL_EFI_STACK_SIZE =0x21000 

        if self.ql.stack_address == 0:
            self.ql.stack_address = self.QL_EFI_STACK_ADDRESS
        if self.ql.stack_size == 0:
            self.ql.stack_size = self.QL_EFI_STACK_SIZE

        if self.ql.path and not self.ql.shellcoder:
            
            # set stack pointer
            self.ql.nprint("[+] Initiate stack address at 0x%x " % self.ql.stack_address)
            self.ql.mem.map(self.ql.stack_address, self.ql.stack_size)

            # Stack should not init at the very bottom. Will cause errors with Dlls
            sp = self.ql.stack_address + self.ql.stack_size - 0x1000

            if self.ql.archtype== QL_X86:
                raise QlErrorArch("[!] Only 64 bit arch supported for now.")
                # self.ql.register(UC_X86_REG_ESP, sp)
                # self.ql.register(UC_X86_REG_EBP, sp)

            elif self.ql.archtype== QL_X8664:
                self.ql.register(UC_X86_REG_RSP, sp)
                self.ql.register(UC_X86_REG_RBP, sp)

            else:
                raise QlErrorArch("[!] Unknown ql.arch")

            if len(self.ql.argv) > 2:
                for dependency in self.ql.argv[1:-1]:
                    if not self.map_and_load(dependency):
                        raise QlErrorFileType("Can't map dependency")
            if len(self.ql.argv) > 1:
                import pickle
                with open(self.ql.argv[-1], 'rb') as f:
                    self.ql.var_store = pickle.load(f)

            # Load main module
            self.map_and_load(self.ql.path)

            self.ql.nprint("[+] Done with loading %s" % self.ql.path)
            self.filepath = b"D:\\" + bytes(self.ql.path.replace("/", "\\"), "utf-8")

        elif self.ql.shellcoder:
            # setup stack memory
            self.ql.mem.map(self.ql.stack_address, self.ql.stack_size)
            if self.ql.archtype== QL_X86:
                self.ql.register(UC_X86_REG_ESP, self.ql.stack_address + 0x3000)
                self.ql.register(UC_X86_REG_EBP, self.ql.stack_address + 0x3000)
            else:
                self.ql.register(UC_X86_REG_RSP, self.ql.stack_address + 0x3000)
                self.ql.register(UC_X86_REG_RBP, self.ql.stack_address + 0x3000)

            # load shellcode in
            self.ql.mem.map(self.ql.code_address, self.ql.code_size)
            self.ql.mem.write(self.ql.code_address, self.ql.shellcoder)
        
        # set SystemTable to image base for now
        #TODO: init a real 
        import ctypes
        pointer_size = ctypes.sizeof(ctypes.c_void_p)
        def convert_struct_to_bytes(st):
            buffer = ctypes.create_string_buffer(ctypes.sizeof(st))
            ctypes.memmove(buffer, ctypes.addressof(st), ctypes.sizeof(st))
            return buffer.raw
        system_table_heap = self.ql.heap.mem_alloc(1024*1024)
        self.ql.system_table_ptr = system_table_heap
        system_table = EFI_SYSTEM_TABLE()
        system_table_heap_ptr = system_table_heap + ctypes.sizeof(EFI_SYSTEM_TABLE)
        
        runtime_services_ptr = system_table_heap_ptr
        system_table.RuntimeServices = runtime_services_ptr
        system_table_heap_ptr += ctypes.sizeof(EFI_RUNTIME_SERVICES)
        system_table_heap_ptr, runtime_services = hook_EFI_RUNTIME_SERVICES(system_table_heap_ptr, self.ql)

        boot_services_ptr = system_table_heap_ptr
        system_table.BootServices = boot_services_ptr
        system_table_heap_ptr += ctypes.sizeof(EFI_BOOT_SERVICES)
        system_table_heap_ptr, boot_services = hook_EFI_BOOT_SERVICES(system_table_heap_ptr, self.ql)

        efi_configuration_table_ptr = system_table_heap_ptr
        system_table.ConfigurationTable = efi_configuration_table_ptr
        system_table.NumberOfTableEntries = 1
        system_table_heap_ptr += ctypes.sizeof(EFI_CONFIGURATION_TABLE)
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

        self.ql.mem.write(runtime_services_ptr, convert_struct_to_bytes(runtime_services))
        self.ql.mem.write(boot_services_ptr, convert_struct_to_bytes(boot_services))
        self.ql.mem.write(efi_configuration_table_ptr, convert_struct_to_bytes(efi_configuration_table))
        self.ql.mem.write(self.ql.system_table_ptr, convert_struct_to_bytes(system_table))

        #return address
        self.ql.end_of_execution_ptr = system_table_heap_ptr
        self.ql.mem.write(self.ql.end_of_execution_ptr, b'\xcc')
        system_table_heap_ptr += pointer_size
        self.ql.hook_address(hook_EndOfExecution, self.ql.end_of_execution_ptr)

    def run(self):
        ql_setup_output(self.ql)

        if (self.ql.until_addr == 0):
            self.ql.until_addr = self.QL_EMU_END
        try:
            if self.ql.shellcoder:
                self.ql.uc.emu_start(self.ql.code_address, self.ql.code_address + len(self.ql.shellcoder))
            else:
                path, entry_point, pe = self.ql.modules.pop(0)
                self.ql.stack_push(self.ql.end_of_execution_ptr)
                self.ql.register(UC_X86_REG_RDX, self.ql.system_table_ptr)
                print(f'Running from 0x{entry_point:x} of {path} to 0x{self.ql.until_addr:x}')
                self.ql.uc.emu_start(entry_point, self.ql.until_addr, 1000*1000)
        except UcError:
            if self.ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
                self.ql.nprint("[+] PC = 0x%x\n" %(self.ql.pc))
                self.ql.mem.show_mapinfo()
                ql_hook_code_disasm(self.ql, self.ql.pc, 64)
            raise

        if self.ql.internal_exception is not None:
            raise self.ql.internal_exception
