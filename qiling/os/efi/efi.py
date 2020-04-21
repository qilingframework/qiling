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
    ql.uc.emu_stop()


class QlOsEfi(QlOs):
    def __init__(self, ql):
        super(QlOsEfi, self).__init__(ql)
        self.ql = ql
        self.user_defined_api = {}
        self.PE_RUN = True
        self.last_error = 0
        # variables used inside hooks
        self.hooks_variables = {}
        self.syscall_count = {}  
        self.HEAP_BASE_ADDR = 0x500000000
        self.HEAP_SIZE = 0x5000000
        self.ql.heap = Heap(self.ql, self.HEAP_BASE_ADDR, self.HEAP_BASE_ADDR + self.HEAP_SIZE)
        self.load()

    def size_align(self, x, k=64):
        n = k*1024
        return x if x % n == 0 else x + n - x % n

    def load(self):        

        """
        initiate UC needs to be in loader, or else it will kill execve
        Note: This is Windows, but for the sake of same with others OS
        """
        self.ql.uc = self.ql.arch.init_uc

        self.pe = pefile.PE(self.ql.path, fast_load=True)
        self.ql.code_address = self.pe.OPTIONAL_HEADER.ImageBase
        self.ql.code_size = self.pe.OPTIONAL_HEADER.SizeOfCode
        self.ql.events = []
        self.ql.handle_dict = {}

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

        # TODO: remove?
        # if self.ql.path and not self.ql.shellcoder:
        #     self.LoaderPE = LoaderPE(self.ql, path =self.ql.path)
        # else:     
        #     raise QlErrorSyscallError("[!] Support efi shell code") 
        
        # due to init memory mapping
        # setup() must come before loader.load() and afer setting up loader
        # setup(self)

        if self.ql.path and not self.ql.shellcoder:
            
            self.pe = pefile.PE(self.ql.path, fast_load=True)
            self.PE_IMAGE_BASE = self.pe.OPTIONAL_HEADER.ImageBase
            self.PE_IMAGE_SIZE = self.size_align(self.pe.OPTIONAL_HEADER.SizeOfImage)

            self.ql.entry_point = self.PE_ENTRY_POINT = self.PE_IMAGE_BASE + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            self.sizeOfStackReserve = self.pe.OPTIONAL_HEADER.SizeOfStackReserve
            self.ql.nprint("[+] Loading %s to 0x%x" % (self.ql.path, self.PE_IMAGE_BASE))
            self.ql.nprint("[+] PE entry point at 0x%x" % self.ql.entry_point)

            # set stack pointer
            self.ql.nprint("[+] Initiate stack address at 0x%x " % self.ql.stack_address)
            self.ql.mem.map(self.ql.stack_address, self.ql.stack_size)

            # Stack should not init at the very bottom. Will cause errors with Dlls
            sp = self.ql.stack_address + self.ql.stack_size - 0x1000

            if self.ql.archtype== QL_X86:
                self.ql.register(UC_X86_REG_ESP, sp)
                self.ql.register(UC_X86_REG_EBP, sp)

            # TODO: remove?
                # if self.pe.is_dll():
                #     self.ql.dprint(D_PROT, '[+] Setting up DllMain args')
                #     load_addr_bytes = self.PE_IMAGE_BASE.to_bytes(length=4, byteorder='little')

                #     self.ql.dprint(D_PROT, '[+] Writing 0x%08X (IMAGE_BASE) to [ESP+4](0x%08X)' % (self.PE_IMAGE_BASE, sp + 0x4))
                #     self.ql.mem.write(sp + 0x4, load_addr_bytes)

                #     self.ql.dprint(D_PROT, '[+] Writing 0x01 (DLL_PROCESS_ATTACH) to [ESP+8](0x%08X)' % (sp + 0x8))
                #     self.ql.mem.write(sp + 0x8, int(1).to_bytes(length=4, byteorder='little'))

            elif self.ql.archtype== QL_X8664:
                self.ql.register(UC_X86_REG_RSP, sp)
                self.ql.register(UC_X86_REG_RBP, sp)

                # TODO: remove?
                # if self.pe.is_dll():
                #     self.ql.dprint(D_PROT, '[+] Setting up DllMain args')

                #     self.ql.dprint(D_PROT, '[+] Setting RCX (arg1) to %16X (IMAGE_BASE)' % (self.PE_IMAGE_BASE))
                #     self.ql.register(UC_X86_REG_RCX, self.PE_IMAGE_BASE)

                #     self.ql.dprint(D_PROT, '[+] Setting RDX (arg2) to 1 (DLL_PROCESS_ATTACH)')
                #     self.ql.register(UC_X86_REG_RDX, 1)
            else:
                raise QlErrorArch("[!] Unknown ql.arch")

            # mmap PE file into memory
            self.ql.mem.map(self.PE_IMAGE_BASE, self.PE_IMAGE_SIZE)
            self.pe.parse_data_directories()
            data = bytearray(self.pe.get_memory_mapped_image())
            self.ql.mem.write(self.PE_IMAGE_BASE, bytes(data))

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
        system_table_ptr = system_table_heap
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


        #return address
        end_of_execution_ptr = system_table_heap_ptr
        system_table_heap_ptr += pointer_size
        self.ql.hook_address(hook_EndOfExecution, end_of_execution_ptr)

        
        

        self.ql.mem.write(runtime_services_ptr, convert_struct_to_bytes(runtime_services))
        self.ql.mem.write(boot_services_ptr, convert_struct_to_bytes(boot_services))
        self.ql.mem.write(system_table_ptr, convert_struct_to_bytes(system_table))


        self.ql.stack_push(end_of_execution_ptr)
        self.ql.register(UC_X86_REG_RDX, system_table_ptr)


        # hook win api
        # self.ql.hook_code(self.hook_winapi)


    # hook WinAPI in PE EMU
    def hook_winapi(self, int, address, size):
        #TODO: check whether we need to hook imports from other modules
        pass


    def run(self):
        ql_setup_output(self.ql)

        if (self.ql.until_addr == 0):
            self.ql.until_addr = self.QL_EMU_END
        try:
            if self.ql.shellcoder:
                self.ql.uc.emu_start(self.ql.code_address, self.ql.code_address + len(self.ql.shellcoder))
            else:
                self.ql.uc.emu_start(self.ql.entry_point, self.ql.until_addr, self.ql.timeout)
        except UcError:
            if self.ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
                self.ql.nprint("[+] PC = 0x%x\n" %(self.ql.pc))
                self.ql.mem.show_mapinfo()
                try:
                    buf = ql.mem.read(ql.pc, 8)
                    self.ql.nprint("[+] %r" % ([hex(_) for _ in buf]))
                    self.ql.nprint("\n")
                    ql_hook_code_disasm(ql, ql.pc, 64)
                except:
                    pass
            raise


        # post_report(self)

        if self.ql.internal_exception is not None:
            raise self.ql.internal_exception
