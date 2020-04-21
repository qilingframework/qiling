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

from qiling.os.windows.fncc import *
from qiling.os.windows.fncc import _get_param_by_index

import pefile


def hook_GetTime(ql):
    print('hook_GetTime')
    ql.pc = ql.stack_pop()
def hook_SetTime(ql):
    print('hook_SetTime')
    ql.pc = ql.stack_pop()
def hook_GetWakeupTime(ql):
    print('hook_GetWakeupTime')
    ql.pc = ql.stack_pop()
def hook_SetWakeupTime(ql):
    print('hook_SetWakeupTime')
    ql.pc = ql.stack_pop()
def hook_SetVirtualAddressMap(ql):
    print('hook_SetVirtualAddressMap')
    ql.pc = ql.stack_pop()
def hook_ConvertPointer(ql):
    print('hook_ConvertPointer')
    ql.pc = ql.stack_pop()

@dxeapi(params={
    "VariableName": WSTRING,
    "VendorGuid": GUID,
    "Attributes": POINTER,
    "DataSize": POINTER,
    "Data": POINTER
})
def hook_GetVariable(self, address, params):
    print(f'hook_GetVariable ({params["VariableName"]}, {params["VendorGuid"]})')
    return 0

def hook_GetNextVariableName(ql):
    print('hook_GetNextVariableName')
    ql.pc = ql.stack_pop()
def hook_SetVariable(ql):
    print('hook_SetVariable')
    ql.pc = ql.stack_pop()
def hook_GetNextHighMonotonicCount(ql):
    print('hook_GetNextHighMonotonicCount')
    ql.pc = ql.stack_pop()
def hook_ResetSystem(ql):
    print('hook_ResetSystem')
    ql.pc = ql.stack_pop()
def hook_UpdateCapsule(ql):
    print('hook_UpdateCapsule')
    ql.pc = ql.stack_pop()
def hook_QueryCapsuleCapabilities(ql):
    print('hook_QueryCapsuleCapabilities')
    ql.pc = ql.stack_pop()
def hook_QueryVariableInfo(ql):
    print('hook_QueryVariableInfo')
    ql.pc = ql.stack_pop()
def hook_RaiseTPL(ql):
    print('hook_RaiseTPL')
    ql.pc = ql.stack_pop()
def hook_RestoreTPL(ql):
    print('hook_RestoreTPL')
    ql.pc = ql.stack_pop()
def hook_AllocatePages(ql):
    print('hook_AllocatePages')
    ql.pc = ql.stack_pop()
def hook_FreePages(ql):
    print('hook_FreePages')
    ql.pc = ql.stack_pop()
def hook_GetMemoryMap(ql):
    print('hook_GetMemoryMap')
    ql.pc = ql.stack_pop()
# IN  EFI_MEMORY_TYPE              PoolType,
#   IN  UINTN                        Size,
#   OUT VOID                         **Buffer
@dxeapi(params={
    "PoolType": UINT,
    "Size": UINT,
    "Buffer": POINTER,
})
def hook_AllocatePool(self, address, params):
    address = self.ql.heap.mem_alloc(params["Size"])
    self.write_int(params["Buffer"], address)
    print(f'hook_AllocatePool({params["PoolType"]}, {params["Size"]}, {params["Buffer"]:x}) = {address:x}')
def hook_FreePool(ql):
    print('hook_FreePool')
    ql.pc = ql.stack_pop()

@dxeapi(params={
    "Type": UINT,
    "NotifyTpl": UINT,
    "NotifyFunction": POINTER,
    "NotifyContext": POINTER,
    "Event": POINTER})
def hook_CreateEvent(self, address, params):
    event_id = len(self.ql.events)+1
    self.ql.events.append((params["NotifyFunction"], params["NotifyContext"]))
    self.write_int(params["Event"], event_id)
    print(f'hook_CreateEvent ({params["Type"]}, {params["NotifyTpl"]}, {params["NotifyFunction"]:x}, {params["NotifyContext"]:x}, {params["Event"]:x}) = {event_id}')
def hook_SetTimer(ql):
    print('hook_SetTimer')
    ql.pc = ql.stack_pop()
def hook_WaitForEvent(ql):
    print('hook_WaitForEvent')
    ql.pc = ql.stack_pop()
def hook_SignalEvent(ql):
    print('hook_SignalEvent')
    ql.pc = ql.stack_pop()
def hook_CloseEvent(ql):
    print('hook_CloseEvent')
    ql.pc = ql.stack_pop()
def hook_CheckEvent(ql):
    print('hook_CheckEvent')
    ql.pc = ql.stack_pop()
def hook_InstallProtocolInterface(ql):
    print('hook_InstallProtocolInterface')
    ql.pc = ql.stack_pop()
def hook_ReinstallProtocolInterface(ql):
    print('hook_ReinstallProtocolInterface')
    ql.pc = ql.stack_pop()
def hook_UninstallProtocolInterface(ql):
    print('hook_UninstallProtocolInterface')
    ql.pc = ql.stack_pop()
def hook_HandleProtocol(ql):
    print('hook_HandleProtocol')
    ql.pc = ql.stack_pop()
def hook_Reserved(ql):
    print('hook_Reserved')
    ql.pc = ql.stack_pop()

@dxeapi(params={
    "Protocol": GUID,
    "Event": POINTER,
    "Registration": POINTER})
def hook_RegisterProtocolNotify(self, address, params):
    print(f'hook_RegisterProtocolNotify ({params["Protocol"]}, {params["Event"]})')
def hook_LocateHandle(ql):
    print('hook_LocateHandle')
    ql.pc = ql.stack_pop()
def hook_LocateDevicePath(ql):
    print('hook_LocateDevicePath')
    ql.pc = ql.stack_pop()
def hook_InstallConfigurationTable(ql):
    print('hook_InstallConfigurationTable')
    ql.pc = ql.stack_pop()
def hook_LoadImage(ql):
    print('hook_LoadImage')
    ql.pc = ql.stack_pop()
def hook_StartImage(ql):
    print('hook_StartImage')
    ql.pc = ql.stack_pop()
def hook_Exit(ql):
    print('hook_Exit')
    ql.pc = ql.stack_pop()
def hook_UnloadImage(ql):
    print('hook_UnloadImage')
    ql.pc = ql.stack_pop()
def hook_ExitBootServices(ql):
    print('hook_ExitBootServices')
    ql.pc = ql.stack_pop()
def hook_GetNextMonotonicCount(ql):
    print('hook_GetNextMonotonicCount')
    ql.pc = ql.stack_pop()
def hook_Stall(ql):
    print('hook_Stall')
    ql.pc = ql.stack_pop()
def hook_SetWatchdogTimer(ql):
    print('hook_SetWatchdogTimer')
    ql.pc = ql.stack_pop()
def hook_ConnectController(ql):
    print('hook_ConnectController')
    ql.pc = ql.stack_pop()
def hook_DisconnectController(ql):
    print('hook_DisconnectController')
    ql.pc = ql.stack_pop()
def hook_OpenProtocol(ql):
    print('hook_OpenProtocol')
    ql.pc = ql.stack_pop()
def hook_CloseProtocol(ql):
    print('hook_CloseProtocol')
    ql.pc = ql.stack_pop()
def hook_OpenProtocolInformation(ql):
    print('hook_OpenProtocolInformation')
    ql.pc = ql.stack_pop()
def hook_ProtocolsPerHandle(ql):
    print('hook_ProtocolsPerHandle')
    ql.pc = ql.stack_pop()
def hook_LocateHandleBuffer(ql):
    print('hook_LocateHandleBuffer')
    ql.pc = ql.stack_pop()
def hook_LocateProtocol(ql):
    print('hook_LocateProtocol')
    ql.pc = ql.stack_pop()
# def hook_sprintf(self, address, params):
#     dst, p_format, p_args = get_function_param(self, 3)
@dxeapi(params={
    "Handle": POINTER})
def hook_InstallMultipleProtocolInterfaces(self, address, params):
    print(f'hook_InstallMultipleProtocolInterfaces {params["Handle"]:x}')
    index = 1
    while _get_param_by_index(self, index) != 0:
        GUID_ptr = _get_param_by_index(self, index)
        protocol_ptr = _get_param_by_index(self, index+1)
        GUID = read_guid(self.ql, GUID_ptr)
        print(f'\t {GUID}, {protocol_ptr:x}')
        index +=2

def hook_UninstallMultipleProtocolInterfaces(ql):
    print('hook_UninstallMultipleProtocolInterfaces')
    ql.pc = ql.stack_pop()
def hook_CalculateCrc32(ql):
    print('hook_CalculateCrc32')
    ql.pc = ql.stack_pop()
def hook_CopyMem(ql):
    print('(hook_CopyMem')
    ql.pc = ql.stack_pop()
def hook_SetMem(ql):
    print('hook_SetMem')
    ql.pc = ql.stack_pop()
def hook_CreateEventEx(ql):
    print('hook_CreateEventEx')
    ql.pc = ql.stack_pop()


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
        runtime_services = EFI_RUNTIME_SERVICES()

        runtime_services.GetTime = system_table_heap_ptr
        self.ql.hook_address(hook_GetTime, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        runtime_services.SetTime = system_table_heap_ptr
        self.ql.hook_address(hook_SetTime, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        runtime_services.GetWakeupTime = system_table_heap_ptr
        self.ql.hook_address(hook_GetWakeupTime, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        runtime_services.SetWakeupTime = system_table_heap_ptr
        self.ql.hook_address(hook_SetWakeupTime, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        runtime_services.SetVirtualAddressMap = system_table_heap_ptr
        self.ql.hook_address(hook_SetVirtualAddressMap, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        runtime_services.ConvertPointer = system_table_heap_ptr
        self.ql.hook_address(hook_ConvertPointer, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        runtime_services.GetVariable = system_table_heap_ptr
        self.ql.hook_address(hook_GetVariable, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        runtime_services.GetNextVariableName = system_table_heap_ptr
        self.ql.hook_address(hook_GetNextVariableName, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        runtime_services.SetVariable = system_table_heap_ptr
        self.ql.hook_address(hook_SetVariable, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        runtime_services.GetNextHighMonotonicCount = system_table_heap_ptr
        self.ql.hook_address(hook_GetNextHighMonotonicCount, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        runtime_services.ResetSystem = system_table_heap_ptr
        self.ql.hook_address(hook_ResetSystem, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        runtime_services.UpdateCapsule = system_table_heap_ptr
        self.ql.hook_address(hook_UpdateCapsule, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        runtime_services.QueryCapsuleCapabilities = system_table_heap_ptr
        self.ql.hook_address(hook_QueryCapsuleCapabilities, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        runtime_services.QueryVariableInfo = system_table_heap_ptr
        self.ql.hook_address(hook_QueryVariableInfo, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size


        boot_services_ptr = system_table_heap_ptr
        system_table.BootServices = boot_services_ptr
        system_table_heap_ptr += ctypes.sizeof(EFI_BOOT_SERVICES)
        boot_services = EFI_BOOT_SERVICES()

        boot_services.RaiseTPL = system_table_heap_ptr
        self.ql.hook_address(hook_RaiseTPL, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.RestoreTPL = system_table_heap_ptr
        self.ql.hook_address(hook_RestoreTPL, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.AllocatePages = system_table_heap_ptr
        self.ql.hook_address(hook_AllocatePages, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.FreePages = system_table_heap_ptr
        self.ql.hook_address(hook_FreePages, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.GetMemoryMap = system_table_heap_ptr
        self.ql.hook_address(hook_GetMemoryMap, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.AllocatePool = system_table_heap_ptr
        self.ql.hook_address(hook_AllocatePool, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.FreePool = system_table_heap_ptr
        self.ql.hook_address(hook_FreePool, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.CreateEvent = system_table_heap_ptr
        self.ql.hook_address(hook_CreateEvent, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.SetTimer = system_table_heap_ptr
        self.ql.hook_address(hook_SetTimer, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.WaitForEvent = system_table_heap_ptr
        self.ql.hook_address(hook_WaitForEvent, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.SignalEvent = system_table_heap_ptr
        self.ql.hook_address(hook_SignalEvent, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.CloseEvent = system_table_heap_ptr
        self.ql.hook_address(hook_CloseEvent, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.CheckEvent = system_table_heap_ptr
        self.ql.hook_address(hook_CheckEvent, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.InstallProtocolInterface = system_table_heap_ptr
        self.ql.hook_address(hook_InstallProtocolInterface, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.ReinstallProtocolInterface = system_table_heap_ptr
        self.ql.hook_address(hook_ReinstallProtocolInterface, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.UninstallProtocolInterface = system_table_heap_ptr
        self.ql.hook_address(hook_UninstallProtocolInterface, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.HandleProtocol = system_table_heap_ptr
        self.ql.hook_address(hook_HandleProtocol, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.Reserved = system_table_heap_ptr
        self.ql.hook_address(hook_Reserved, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.RegisterProtocolNotify = system_table_heap_ptr
        self.ql.hook_address(hook_RegisterProtocolNotify, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.LocateHandle = system_table_heap_ptr
        self.ql.hook_address(hook_LocateHandle, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.LocateDevicePath = system_table_heap_ptr
        self.ql.hook_address(hook_LocateDevicePath, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.InstallConfigurationTable = system_table_heap_ptr
        self.ql.hook_address(hook_InstallConfigurationTable, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.LoadImage = system_table_heap_ptr
        self.ql.hook_address(hook_LoadImage, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.StartImage = system_table_heap_ptr
        self.ql.hook_address(hook_StartImage, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.Exit = system_table_heap_ptr
        self.ql.hook_address(hook_Exit, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.UnloadImage = system_table_heap_ptr
        self.ql.hook_address(hook_UnloadImage, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.ExitBootServices = system_table_heap_ptr
        self.ql.hook_address(hook_ExitBootServices, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.GetNextMonotonicCount = system_table_heap_ptr
        self.ql.hook_address(hook_GetNextMonotonicCount, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.Stall = system_table_heap_ptr
        self.ql.hook_address(hook_Stall, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.SetWatchdogTimer = system_table_heap_ptr
        self.ql.hook_address(hook_SetWatchdogTimer, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.ConnectController = system_table_heap_ptr
        self.ql.hook_address(hook_ConnectController, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.DisconnectController = system_table_heap_ptr
        self.ql.hook_address(hook_DisconnectController, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.OpenProtocol = system_table_heap_ptr
        self.ql.hook_address(hook_OpenProtocol, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.CloseProtocol = system_table_heap_ptr
        self.ql.hook_address(hook_CloseProtocol, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.OpenProtocolInformation = system_table_heap_ptr
        self.ql.hook_address(hook_OpenProtocolInformation, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.ProtocolsPerHandle = system_table_heap_ptr
        self.ql.hook_address(hook_ProtocolsPerHandle, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.LocateHandleBuffer = system_table_heap_ptr
        self.ql.hook_address(hook_LocateHandleBuffer, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.LocateProtocol = system_table_heap_ptr
        self.ql.hook_address(hook_LocateProtocol, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.InstallMultipleProtocolInterfaces = system_table_heap_ptr
        self.ql.hook_address(hook_InstallMultipleProtocolInterfaces, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.UninstallMultipleProtocolInterfaces = system_table_heap_ptr
        self.ql.hook_address(hook_UninstallMultipleProtocolInterfaces, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.CalculateCrc32 = system_table_heap_ptr
        self.ql.hook_address(hook_CalculateCrc32, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.CopyMem = system_table_heap_ptr
        self.ql.hook_address(hook_CopyMem, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.SetMem = system_table_heap_ptr
        self.ql.hook_address(hook_SetMem, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size
        boot_services.CreateEventEx = system_table_heap_ptr
        self.ql.hook_address(hook_CreateEventEx, system_table_heap_ptr)
        system_table_heap_ptr += pointer_size


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
