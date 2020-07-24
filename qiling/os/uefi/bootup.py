#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from uuid import UUID
from binascii import crc32
from qiling.const import *

from .utils import *
from .type64 import *
from .mm_system_table_type import *
from .shutdown import *
from .fncc import *
from .const import *
from qiling.os.const import *

@dxeapi(params={
    "NewTpl": ULONGLONG,
})
def hook_RaiseTPL(ql, address, params):
    tpl = ql.loader.tpl
    ql.loader.tpl = params["NewTpl"]
    return tpl

@dxeapi(params={
    "OldTpl": ULONGLONG,
})
def hook_RestoreTPL(ql, address, params):
    ql.loader.tpl = params["OldTpl"]

@dxeapi(params={
    "type": ULONGLONG,
    "MemoryType": ULONGLONG,
    "Pages": ULONGLONG,
    "Memory": POINTER, #POINTER_T(ctypes.c_uint64)
})
def hook_AllocatePages(ql, address, params):
    AllocateAnyPages = 0
    AllocateMaxAddress = 1
    AllocateAddress = 2
    PageSize = 4096
    if params['type'] == AllocateAddress:
        address =  read_int64(ql, params["Memory"])
        ql.mem.map(address, params["Pages"]*PageSize)
    else:
        address = ql.loader.heap.alloc(params["Pages"]*PageSize)
        write_int64(ql, params["Memory"], address)
    return EFI_SUCCESS

@dxeapi(params={
    "Memory": ULONGLONG,
    "Pages": ULONGLONG,
})
def hook_FreePages(ql, address, params):
    return EFI_SUCCESS

@dxeapi(params={
    "a0": POINTER, #POINTER_T(ctypes.c_uint64)
    "a1": POINTER, #POINTER_T(struct_EFI_MEMORY_DESCRIPTOR)
    "a2": POINTER, #POINTER_T(ctypes.c_uint64)
    "a3": POINTER, #POINTER_T(ctypes.c_uint64)
    "a4": POINTER, #POINTER_T(ctypes.c_uint32)
})
def hook_GetMemoryMap(ql, address, params):
    return EFI_SUCCESS

@dxeapi(params={
    "PoolType": UINT,
    "Size": UINT,
    "Buffer": POINTER,
})
def hook_AllocatePool(ql, address, params):
    address = ql.loader.heap.alloc(params["Size"])
    write_int64(ql, params["Buffer"], address)
    return EFI_SUCCESS if address else EFI_OUT_OF_RESOURCES

@dxeapi(params={
    "Buffer": POINTER, #POINTER_T(None)
})
def hook_FreePool(ql, address, params):
    address = params["Buffer"]
    freed = ql.loader.heap.free(address)
    return EFI_SUCCESS if freed else EFI_INVALID_PARAMETER 

@dxeapi(params={
    "Type": UINT,
    "NotifyTpl": UINT,
    "NotifyFunction": POINTER,
    "NotifyContext": POINTER,
    "Event": POINTER})
def hook_CreateEvent(ql, address, params):
    return CreateEvent(ql, address, params)

@dxeapi(params={
    "a0": POINTER, #POINTER_T(None)
    "a1": ULONGLONG,
    "a2": ULONGLONG,
})
def hook_SetTimer(ql, address, params):
    return EFI_SUCCESS

@dxeapi(params={
    "a0": ULONGLONG,
    "a1": POINTER, #POINTER_T(POINTER_T(None))
    "a2": POINTER, #POINTER_T(ctypes.c_uint64)
})
def hook_WaitForEvent(ql, address, params):
    return EFI_SUCCESS

def SignalEvent(ql, event_id):
    if event_id in ql.loader.events:
        event = ql.loader.events[event_id]
        if not event["Set"]:
            event["Set"] = True
            notify_func = event["NotifyFunction"]
            notify_context = event["NotifyContext"]
            if ql.os.notify_immediately:
                ql.nprint(f'[+] Notify event:{event_id} calling:{notify_func:x} context:{notify_context:x}')
                # X64 shadow store - The caller is responsible for allocating space for parameters to the callee, and must always allocate sufficient space to store four register parameters
                ql.reg.rsp -= pointer_size * 4 
                ql.stack_push(ql.loader.OOO_EOE_ptr) # Return address from the notify function.
                ql.stack_push(notify_func) # Return address from here -> the notify function.
                ql.loader.OOO_EOE_callbacks.append(None) # We don't need a callback.
                ql.reg.rcx = notify_context
            else:
                ql.loader.notify_list.append((event_id, notify_func, notify_context))
        return EFI_SUCCESS
    else:
        return EFI_INVALID_PARAMETER

@dxeapi(params={
    "Event": POINTER, #POINTER_T(None)
})
def hook_SignalEvent(ql, address, params):
    event_id = params["Event"]
    return SignalEvent(ql, event_id)

@dxeapi(params={
    "Event": POINTER, #POINTER_T(None)
})
def hook_CloseEvent(ql, address, params):
    del ql.loader.events[params["Event"]]
    return EFI_SUCCESS

@dxeapi(params={
    "Event": POINTER, #POINTER_T(None)
})
def hook_CheckEvent(ql, address, params):
    return EFI_SUCCESS if ql.loader.events[params["Event"]]["Set"] else EFI_NOT_READY

@dxeapi(params={
    "Handle": POINTER, #POINTER_T(POINTER_T(None))
    "Protocol": GUID,
    "InterfaceType": ULONGLONG,
    "Interface": POINTER, #POINTER_T(None)
})
def hook_InstallProtocolInterface(ql, address, params):
    dic = {}
    handle = read_int64(ql, params["Handle"])
    if handle == 0:
        handle = ql.loader.heap.alloc(1)
    if handle in ql.loader.handle_dict:
        dic = ql.loader.handle_dict[handle]
    dic[params["Protocol"]] = params["Interface"]
    ql.loader.handle_dict[handle] = dic
    check_and_notify_protocols(ql)
    write_int64(ql, params["Handle"], handle)
    return EFI_SUCCESS

@dxeapi(params={
    "Handle": POINTER, #POINTER_T(None)
    "Protocol": GUID,
    "OldInterface": POINTER, #POINTER_T(None)
    "NewInterface": POINTER, #POINTER_T(None)
})
def hook_ReinstallProtocolInterface(ql, address, params):
    handle = params["Handle"]
    if handle not in ql.loader.handle_dict:
        return EFI_NOT_FOUND
    dic = ql.loader.handle_dict[handle]
    protocol = params["Protocol"]
    if protocol not in dic:
        return EFI_NOT_FOUND
    dic[protocol] = params["NewInterface"]
    return EFI_SUCCESS

@dxeapi(params={
    "Handle": POINTER, #POINTER_T(None)
    "Protocol": GUID,
    "Interface": POINTER, #POINTER_T(None)
})
def hook_UninstallProtocolInterface(ql, address, params):
    handle = params["Handle"]
    if handle not in ql.loader.handle_dict:
        return EFI_NOT_FOUND
    dic = ql.loader.handle_dict[handle]
    protocol = params["Protocol"]
    if protocol not in dic:
        return EFI_NOT_FOUND
    del dic[protocol]
    return EFI_SUCCESS

@dxeapi(params={
    "Handle": POINTER, #POINTER_T(None)
    "Protocol": GUID,
    "Interface": POINTER, #POINTER_T(POINTER_T(None))
})
def hook_HandleProtocol(ql, address, params):
    handle = params["Handle"]
    protocol = params["Protocol"]
    interface = params['Interface']
    if handle in ql.loader.handle_dict:
        if protocol in ql.loader.handle_dict[handle]:
            write_int64(ql, interface, ql.loader.handle_dict[handle][protocol])
            return EFI_SUCCESS
    return EFI_NOT_FOUND

@dxeapi(params={
    "Protocol": GUID,
    "Event": POINTER,
    "Registration": POINTER})
def hook_RegisterProtocolNotify(ql, address, params):
    if params['Event'] in ql.loader.events:
        ql.loader.events[params['Event']]['Guid'] = params["Protocol"]
        check_and_notify_protocols(ql)
        return EFI_SUCCESS
    return EFI_INVALID_PARAMETER



@dxeapi(params={
    "SearchType": ULONGLONG,
    "Protocol": GUID,
    "SearchKey": POINTER, #POINTER_T(None)
    "BufferSize": POINTER, #POINTER_T(ctypes.c_uint64)
    "Buffer": POINTER, #POINTER_T(POINTER_T(None))
})
def hook_LocateHandle(ql, address, params):
    buffer_size, handles = LocateHandles(ql, address, params)
    if len(handles) == 0:
        return EFI_NOT_FOUND
    ret = EFI_BUFFER_TOO_SMALL
    if read_int64(ql, params["BufferSize"]) >= buffer_size:
        ptr = params["Buffer"]
        for handle in handles:
            write_int64(ql, ptr, handle)
            ptr += pointer_size
        ret = EFI_SUCCESS
    write_int64(ql, params["BufferSize"], buffer_size)
    return ret
    

@dxeapi(params={
    "a0": GUID,
    "a1": POINTER, #POINTER_T(POINTER_T(struct_EFI_DEVICE_PATH_PROTOCOL))
    "a2": POINTER, #POINTER_T(POINTER_T(None))
})
def hook_LocateDevicePath(ql, address, params):
    return EFI_SUCCESS

@dxeapi(params={
    "Guid": GUID,
    "Table": POINTER, #POINTER_T(None)
})
def hook_InstallConfigurationTable(ql, address, params):
    guid = params["Guid"]
    uuid = UUID(guid)
    efi_configuration_table = EFI_CONFIGURATION_TABLE()
    if guid in ql.loader.efi_configuration_table:
        index = ql.loader.efi_configuration_table.index(guid)
    else:
        index = len(ql.loader.efi_configuration_table)
        ql.loader.efi_configuration_table.append(guid)
    
    address = (index * ctypes.sizeof(efi_configuration_table)) + ql.loader.efi_configuration_table_ptr
    efi_configuration_table.VendorGuid.Data1 = uuid.fields[0]
    efi_configuration_table.VendorGuid.Data2 = uuid.fields[1]
    efi_configuration_table.VendorGuid.Data3 = uuid.fields[2]
    guid_last_bytes = uuid.bytes_le[8:]
    for i in range(len(guid_last_bytes)):
        efi_configuration_table.VendorGuid.Data4[i] = guid_last_bytes[i]
    
    efi_configuration_table.VendorTable = params["Table"]
    ql.mem.write(address, convert_struct_to_bytes(efi_configuration_table))
    return EFI_SUCCESS

@dxeapi(params={
    "a0": ULONGLONG,
    "a1": POINTER, #POINTER_T(None)
    "a2": POINTER, #POINTER_T(struct_EFI_DEVICE_PATH_PROTOCOL)
    "a3": POINTER, #POINTER_T(None)
    "a4": ULONGLONG,
    "a5": POINTER, #POINTER_T(POINTER_T(None))
})
def hook_LoadImage(ql, address, params):
    return EFI_SUCCESS

@dxeapi(params={
    "a0": POINTER, #POINTER_T(None)
    "a1": POINTER, #POINTER_T(ctypes.c_uint64)
    "a2": POINTER, #POINTER_T(POINTER_T(ctypes.c_uint16))
})
def hook_StartImage(ql, address, params):
    return EFI_SUCCESS

@dxeapi(params={
    "a0": POINTER, #POINTER_T(None)
    "a1": ULONGLONG,
    "a2": ULONGLONG,
    "a3": POINTER, #POINTER_T(ctypes.c_uint16)
})
def hook_Exit(ql, address, params):
    ql.nprint(f'hook_Exit')
    ql.uc.emu_stop()
    return EFI_SUCCESS

@dxeapi(params={
    "a0": POINTER, #POINTER_T(None)
})
def hook_UnloadImage(ql, address, params):
    return EFI_SUCCESS

@dxeapi(params={
    "a0": POINTER, #POINTER_T(None)
    "a1": ULONGLONG,
})
def hook_ExitBootServices(ql, address, params):
    ql.nprint(f'hook_ExitBootServices')
    ql.uc.emu_stop()
    return EFI_SUCCESS

@dxeapi(params={
    "Count": POINTER, #POINTER_T(ctypes.c_uint64)
})
def hook_GetNextMonotonicCount(ql, address, params):
    ql.os.monotonic_count += 1
    write_int64(ql, params["Count"], ql.os.monotonic_count)
    return EFI_SUCCESS

@dxeapi(params={
    "a0": ULONGLONG,
})
def hook_Stall(ql, address, params):
    return EFI_SUCCESS

@dxeapi(params={
    "a0": ULONGLONG,
    "a1": ULONGLONG,
    "a2": ULONGLONG,
    "a3": POINTER, #POINTER_T(ctypes.c_uint16)
})
def hook_SetWatchdogTimer(ql, address, params):
    return EFI_SUCCESS

@dxeapi(params={
    "a0": POINTER, #POINTER_T(None)
    "a1": POINTER, #POINTER_T(POINTER_T(None))
    "a2": POINTER, #POINTER_T(struct_EFI_DEVICE_PATH_PROTOCOL)
    "a3": ULONGLONG,
})
def hook_ConnectController(ql, address, params):
    return EFI_SUCCESS

@dxeapi(params={
    "a0": POINTER, #POINTER_T(None)
    "a1": POINTER, #POINTER_T(None)
    "a2": POINTER, #POINTER_T(None)
})
def hook_DisconnectController(ql, address, params):
    return EFI_SUCCESS

@dxeapi(params={
    "Handle": POINTER, #POINTER_T(None)
    "Protocol": GUID,
    "Interface": POINTER, #POINTER_T(POINTER_T(None))
    "AgentHandle": POINTER, #POINTER_T(None)
    "ControllerHandle": POINTER, #POINTER_T(None)
    "Attributes": UINT,
})
def hook_OpenProtocol(ql, address, params):
    return LocateProtocol(ql, address, params)

@dxeapi(params={
    "Handle": POINTER, #POINTER_T(None)
    "Protocol": GUID,
    "AgentHandle": POINTER, #POINTER_T(None)
    "ControllerHandle": POINTER, #POINTER_T(None)
})
def hook_CloseProtocol(ql, address, params):
    return EFI_SUCCESS

@dxeapi(params={
    "Handle": POINTER, #POINTER_T(None)
    "Protocol": GUID,
    "EntryBuffer": POINTER, #POINTER_T(POINTER_T(struct_EFI_OPEN_PROTOCOL_INFORMATION_ENTRY))
    "EntryCount": POINTER, #POINTER_T(ctypes.c_uint64)
})
def hook_OpenProtocolInformation(ql, address, params):
    return EFI_NOT_FOUND

@dxeapi(params={
    "a0": POINTER, #POINTER_T(None)
    "a1": GUID,
    "a2": POINTER, #POINTER_T(ctypes.c_uint64)
})
def hook_ProtocolsPerHandle(ql, address, params):
    return EFI_SUCCESS

@dxeapi(params={
    "SearchType": ULONGLONG,
    "Protocol": GUID,
    "SearchKey": POINTER, #POINTER_T(None)
    "NoHandles": POINTER, #POINTER_T(ctypes.c_uint64)
    "Buffer": POINTER, #POINTER_T(POINTER_T(POINTER_T(None)))
})
def hook_LocateHandleBuffer(ql, address, params):
    buffer_size, handles = LocateHandles(ql, address, params)
    write_int64(ql, params["NoHandles"], len(handles))
    if len(handles) == 0:
        return EFI_NOT_FOUND
    address = ql.loader.heap.alloc(buffer_size)
    write_int64(ql, params["Buffer"], address)
    if address == 0:
        return EFI_OUT_OF_RESOURCES
    for handle in handles:
        write_int64(ql, address, handle)
        address += pointer_size
    return EFI_SUCCESS

@dxeapi(params={
    "Protocol": GUID,
    "Registration": POINTER, #POINTER_T(None)
    "Interface": POINTER, #POINTER_T(POINTER_T(None))
})
def hook_LocateProtocol(ql, address, params):
    return LocateProtocol(ql, address, params)

@dxeapi(params={
    "Handle": POINTER})
def hook_InstallMultipleProtocolInterfaces(ql, address, params):
    handle = read_int64(ql, params["Handle"])
    if handle == 0:
        handle = ql.loader.heap.alloc(1)
    ql.nprint(f'hook_InstallMultipleProtocolInterfaces {handle:x}')
    dic = {}
    if handle in ql.loader.handle_dict:
        dic = ql.loader.handle_dict[handle]
    
    index = 1
    while ql.os.get_param_by_index(index) != 0:
        GUID_ptr = ql.os.get_param_by_index(index)
        protocol_ptr = ql.os.get_param_by_index(index+1)
        GUID = str(ql.os.read_guid(GUID_ptr))
        ql.nprint(f'\t {GUID}, {protocol_ptr:x}')
        dic[GUID] = protocol_ptr
        index +=2
    ql.loader.handle_dict[handle] = dic
    check_and_notify_protocols(ql)
    write_int64(ql, params["Handle"], handle)
    return EFI_SUCCESS

@dxeapi(params={
    "Handle": POINTER, #POINTER_T(None)
})
def hook_UninstallMultipleProtocolInterfaces(ql, address, params):
    handle = params["Handle"]
    ql.nprint(f'hook_UninstallMultipleProtocolInterfaces {handle:x}')
    if handle not in ql.loader.handle_dict:
        return EFI_NOT_FOUND
    index = 1
    while ql.os.get_param_by_index(index) != 0:
        GUID_ptr = ql.os.get_param_by_index(index)
        protocol_ptr = ql.os.get_param_by_index(index+1)
        GUID = str(ql.os.read_guid(GUID_ptr))
        ql.nprint(f'\t {GUID}, {protocol_ptr:x}')
        dic = ql.loader.handle_dict[handle]
        if GUID not in dic:
            return EFI_INVALID_PARAMETER
        del dic[GUID]
        index +=2
    return EFI_SUCCESS

@dxeapi(params={
    "Data": POINTER, #POINTER_T(None)
    "DataSize": ULONGLONG,
    "Crc32": POINTER, #POINTER_T(ctypes.c_uint32)
})
def hook_CalculateCrc32(ql, address, params):
    data = bytes(ql.mem.read(params['Data'], params['DataSize']))
    write_int32(ql, params['Crc32'], crc32(data))
    return EFI_SUCCESS

@dxeapi(params={
    "Destination": POINTER, #POINTER_T(None)
    "Source": POINTER, #POINTER_T(None)
    "Length": ULONGLONG,
})
def hook_CopyMem(ql, address, params):
    data = bytes(ql.mem.read(params['Source'], params['Length']))
    ql.mem.write(params['Destination'], data)

@dxeapi(params={
    "Buffer": POINTER, #POINTER_T(None)
    "Size": ULONGLONG,
    "Value": BYTE,
})
def hook_SetMem(ql, address, params):
    ptr = params["Buffer"]
    value = struct.pack('B',params["Value"] & 0xff)
    for i in range(0, params["Size"]):
        ql.mem.write(ptr+i, value)

@dxeapi(params={
    "Type": UINT,
    "NotifyTpl": ULONGLONG,
    "NotifyFunction": POINTER, #POINTER_T(ctypes.CFUNCTYPE(None, POINTER_T(None), POINTER_T(None)))
    "NotifyContext": POINTER, #POINTER_T(None)
    "EventGroup": GUID,
    "Event": POINTER, #POINTER_T(POINTER_T(None))
})
def hook_CreateEventEx(ql, address, params):
    return CreateEvent(ql, address, params)


def CreateEvent(ql, address, params):
    event_id = len(ql.loader.events)
    event_dic = {"NotifyFunction": params["NotifyFunction"], "NotifyContext": params["NotifyContext"], "Guid": "", "Set": False}
    if "EventGroup" in params:
        event_dic["EventGroup"] =  params["EventGroup"]
    
    ql.loader.events[event_id] = event_dic
    write_int64(ql, params["Event"], event_id)
    return EFI_SUCCESS

def hook_EFI_BOOT_SERVICES(ql, start_ptr):
    ql.os.monotonic_count = 0

    efi_boot_services = EFI_BOOT_SERVICES()
    efi_mm_system_table = EFI_MM_SYSTEM_TABLE()

    ptr = start_ptr
    efi_boot_services.RaiseTPL = ptr
    ql.hook_address(hook_RaiseTPL, ptr)
    ptr += pointer_size
    efi_boot_services.RestoreTPL = ptr
    ql.hook_address(hook_RestoreTPL, ptr)
    ptr += pointer_size
    efi_boot_services.AllocatePages = ptr
    efi_mm_system_table.MmAllocatePages = ptr
    ql.hook_address(hook_AllocatePages, ptr)
    ptr += pointer_size
    efi_boot_services.FreePages = ptr
    efi_mm_system_table.MmFreePages = ptr
    ql.hook_address(hook_FreePages, ptr)
    ptr += pointer_size
    efi_boot_services.GetMemoryMap = ptr
    ql.hook_address(hook_GetMemoryMap, ptr)
    ptr += pointer_size
    efi_boot_services.AllocatePool = ptr
    efi_mm_system_table.MmAllocatePool = ptr
    ql.hook_address(hook_AllocatePool, ptr)
    ptr += pointer_size
    efi_boot_services.FreePool = ptr
    efi_mm_system_table.MmFreePool = ptr
    ql.hook_address(hook_FreePool, ptr)
    ptr += pointer_size
    efi_boot_services.CreateEvent = ptr
    ql.hook_address(hook_CreateEvent, ptr)
    ptr += pointer_size
    efi_boot_services.SetTimer = ptr
    ql.hook_address(hook_SetTimer, ptr)
    ptr += pointer_size
    efi_boot_services.WaitForEvent = ptr
    ql.hook_address(hook_WaitForEvent, ptr)
    ptr += pointer_size
    efi_boot_services.SignalEvent = ptr
    ql.hook_address(hook_SignalEvent, ptr)
    ptr += pointer_size
    efi_boot_services.CloseEvent = ptr
    ql.hook_address(hook_CloseEvent, ptr)
    ptr += pointer_size
    efi_boot_services.CheckEvent = ptr
    ql.hook_address(hook_CheckEvent, ptr)
    ptr += pointer_size
    efi_boot_services.InstallProtocolInterface = ptr
    efi_mm_system_table.MmInstallProtocolInterface = ptr
    ql.hook_address(hook_InstallProtocolInterface, ptr)
    ptr += pointer_size
    efi_boot_services.ReinstallProtocolInterface = ptr
    ql.hook_address(hook_ReinstallProtocolInterface, ptr)
    ptr += pointer_size
    efi_boot_services.UninstallProtocolInterface = ptr
    efi_mm_system_table.MmUninstallProtocolInterface = ptr
    ql.hook_address(hook_UninstallProtocolInterface, ptr)
    ptr += pointer_size
    efi_boot_services.HandleProtocol = ptr
    efi_mm_system_table.MmHandleProtocol = ptr
    ql.hook_address(hook_HandleProtocol, ptr)
    ptr += pointer_size
    efi_boot_services.RegisterProtocolNotify = ptr
    efi_mm_system_table.MmRegisterProtocolNotify = ptr
    ql.hook_address(hook_RegisterProtocolNotify, ptr)
    ptr += pointer_size
    efi_boot_services.LocateHandle = ptr
    efi_mm_system_table.MmLocateHandle = ptr
    ql.hook_address(hook_LocateHandle, ptr)
    ptr += pointer_size
    efi_boot_services.LocateDevicePath = ptr
    ql.hook_address(hook_LocateDevicePath, ptr)
    ptr += pointer_size
    efi_boot_services.InstallConfigurationTable = ptr
    efi_mm_system_table.MmInstallConfigurationTable = ptr
    ql.hook_address(hook_InstallConfigurationTable, ptr)
    ptr += pointer_size
    efi_boot_services.LoadImage = ptr
    ql.hook_address(hook_LoadImage, ptr)
    ptr += pointer_size
    efi_boot_services.StartImage = ptr
    ql.hook_address(hook_StartImage, ptr)
    ptr += pointer_size
    efi_boot_services.Exit = ptr
    ql.hook_address(hook_Exit, ptr)
    ptr += pointer_size
    efi_boot_services.UnloadImage = ptr
    ql.hook_address(hook_UnloadImage, ptr)
    ptr += pointer_size
    efi_boot_services.ExitBootServices = ptr
    ql.hook_address(hook_ExitBootServices, ptr)
    ptr += pointer_size
    efi_boot_services.GetNextMonotonicCount = ptr
    ql.hook_address(hook_GetNextMonotonicCount, ptr)
    ptr += pointer_size
    efi_boot_services.Stall = ptr
    ql.hook_address(hook_Stall, ptr)
    ptr += pointer_size
    efi_boot_services.SetWatchdogTimer = ptr
    ql.hook_address(hook_SetWatchdogTimer, ptr)
    ptr += pointer_size
    efi_boot_services.ConnectController = ptr
    ql.hook_address(hook_ConnectController, ptr)
    ptr += pointer_size
    efi_boot_services.DisconnectController = ptr
    ql.hook_address(hook_DisconnectController, ptr)
    ptr += pointer_size
    efi_boot_services.OpenProtocol = ptr
    ql.hook_address(hook_OpenProtocol, ptr)
    ptr += pointer_size
    efi_boot_services.CloseProtocol = ptr
    ql.hook_address(hook_CloseProtocol, ptr)
    ptr += pointer_size
    efi_boot_services.OpenProtocolInformation = ptr
    ql.hook_address(hook_OpenProtocolInformation, ptr)
    ptr += pointer_size
    efi_boot_services.ProtocolsPerHandle = ptr
    ql.hook_address(hook_ProtocolsPerHandle, ptr)
    ptr += pointer_size
    efi_boot_services.LocateHandleBuffer = ptr
    ql.hook_address(hook_LocateHandleBuffer, ptr)
    ptr += pointer_size
    efi_boot_services.LocateProtocol = ptr
    efi_mm_system_table.MmLocateProtocol = ptr
    ql.hook_address(hook_LocateProtocol, ptr)
    ptr += pointer_size
    efi_boot_services.InstallMultipleProtocolInterfaces = ptr
    ql.hook_address(hook_InstallMultipleProtocolInterfaces, ptr)
    ptr += pointer_size
    efi_boot_services.UninstallMultipleProtocolInterfaces = ptr
    ql.hook_address(hook_UninstallMultipleProtocolInterfaces, ptr)
    ptr += pointer_size
    efi_boot_services.CalculateCrc32 = ptr
    ql.hook_address(hook_CalculateCrc32, ptr)
    ptr += pointer_size
    efi_boot_services.CopyMem = ptr
    ql.hook_address(hook_CopyMem, ptr)
    ptr += pointer_size
    efi_boot_services.SetMem = ptr
    ql.hook_address(hook_SetMem, ptr)
    ptr += pointer_size
    efi_boot_services.CreateEventEx = ptr
    ql.hook_address(hook_CreateEventEx, ptr)
    ptr += pointer_size
    return (ptr, efi_boot_services, efi_mm_system_table)

