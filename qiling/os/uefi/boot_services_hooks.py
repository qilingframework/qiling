from uuid import UUID
from binascii import crc32
from qiling.const import *
from qiling.os.uefi.utils import *
from qiling.os.uefi.fncc import *
from qiling.os.uefi.uefi_types_64 import *
from qiling.os.uefi.other_hooks import *
from qiling.os.windows.fncc import *
from qiling.os.windows.fncc import _get_param_by_index

pointer_size = 8

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
def hook_RestoreTPL(ql, ctx, address, params):
    ql.loader.tpl = params["OldTpl"]

@dxeapi(params={
    "type": ULONGLONG,
    "MemoryType": ULONGLONG,
    "Pages": ULONGLONG,
    "Memory": POINTER, #POINTER_T(ctypes.c_uint64)
})
def hook_AllocatePages(ql, ctx, address, params):
    AllocateAnyPages = 0
    AllocateMaxAddress = 1
    AllocateAddress = 2
    PageSize = 4096
    if params['type'] == AllocateAddress:
        address = ctx.read_int64(params["Memory"])
        ql.mem.map(address, params["Pages"]*PageSize)
    else:
        address = ctx.ql.heap.mem_alloc(params["Pages"]*PageSize)
        ctx.write_int64(params["Memory"], address)
    return address

@dxeapi(params={
    "Memory": ULONGLONG,
    "Pages": ULONGLONG,
})
def hook_FreePages(ql, ctx, address, params):
    return ctx.EFI_SUCCESS

@dxeapi(params={
    "a0": POINTER, #POINTER_T(ctypes.c_uint64)
    "a1": POINTER, #POINTER_T(struct_EFI_MEMORY_DESCRIPTOR)
    "a2": POINTER, #POINTER_T(ctypes.c_uint64)
    "a3": POINTER, #POINTER_T(ctypes.c_uint64)
    "a4": POINTER, #POINTER_T(ctypes.c_uint32)
})
def hook_GetMemoryMap(ql, ctx, address, params):
    return ctx.EFI_SUCCESS

@dxeapi(params={
    "PoolType": UINT,
    "Size": UINT,
    "Buffer": POINTER,
})
def hook_AllocatePool(ql, address, params):
    address = ql.loader.heap.mem_alloc(params["Size"])
    ql.os.ctx.write_int64(params["Buffer"], address)
    return address

@dxeapi(params={
    "Buffer": POINTER, #POINTER_T(None)
})
def hook_FreePool(ql, ctx, address, params):
    address = params["Buffer"]
    ql.heap.mem_free(address)
    return ctx.EFI_SUCCESS

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
def hook_SetTimer(ctx, address, params):
    return ctx.EFI_SUCCESS

@dxeapi(params={
    "a0": ULONGLONG,
    "a1": POINTER, #POINTER_T(POINTER_T(None))
    "a2": POINTER, #POINTER_T(ctypes.c_uint64)
})
def hook_WaitForEvent(ctx, address, params):
    return ctx.EFI_SUCCESS

def SignalEvent(ctx, event_id):
    if event_id in ctx.ql.events:
        event = ctx.ql.events[event_id]
        if not event["Set"]:
            event["Set"] = True
            notify_func = event["NotifyFunction"]
            notify_context = event["NotifyContext"]
            if ctx.ql.notify_immediately:
                ctx.ql.hook_address(hook_EndOfNotify, ctx.ql.notify_ptr)
                ctx.ql.nprint(f'Notify event:{event_id} calling:{notify_func:x} context:{notify_context:x}')
                ctx.ql.notify_return_address = ctx.ql.stack_pop()
                ctx.ql.stack_push(ctx.ql.notify_ptr) # Return address from the notify function
                ctx.ql.stack_push(notify_func) # Return address from here -> the notify function.
                ctx.ql.reg.rcx = notify_context
            else:
                ctx.ql.notify_list.append((event_id, notify_func, notify_context))
        return ctx.EFI_SUCCESS
    else:
        return ctx.EFI_INVALID_PARAMETER

@dxeapi(params={
    "Event": POINTER, #POINTER_T(None)
})
def hook_SignalEvent(ctx, address, params):
    event_id = params["Event"]
    return SignalEvent(ctx, event_id)

@dxeapi(params={
    "Event": POINTER, #POINTER_T(None)
})
def hook_CloseEvent(ctx, address, params):
    del ctx.ql.events[params["Event"]]
    return ctx.EFI_SUCCESS

@dxeapi(params={
    "Event": POINTER, #POINTER_T(None)
})
def hook_CheckEvent(ctx, address, params):
    return ctx.EFI_SUCCESS if ctx.ql.events[params["Event"]]["Set"] else ctx.EFI_NOT_READY

@dxeapi(params={
    "Handle": POINTER, #POINTER_T(POINTER_T(None))
    "Protocol": GUID,
    "InterfaceType": ULONGLONG,
    "Interface": POINTER, #POINTER_T(None)
})
def hook_InstallProtocolInterface(ctx, address, params):
    dic = {}
    handle = params["Handle"]
    if handle in ctx.ql.handle_dict:
        dic = ctx.ql.handle_dict[handle]
    dic[params["Protocol"]] = params["Interface"]
    ctx.ql.handle_dict[handle] = dic
    check_and_notify_protocols(ql)
    return ctx.EFI_SUCCESS

@dxeapi(params={
    "Handle": POINTER, #POINTER_T(None)
    "Protocol": GUID,
    "OldInterface": POINTER, #POINTER_T(None)
    "NewInterface": POINTER, #POINTER_T(None)
})
def hook_ReinstallProtocolInterface(ctx, address, params):
    handle = params["Handle"]
    if handle not in ctx.ql.handle_dict:
        return ctx.EFI_NOT_FOUND
    dic = ctx.ql.handle_dict[handle]
    protocol = params["Protocol"]
    if protocol not in dic:
        return ctx.EFI_NOT_FOUND
    dic[protocol] = params["NewInterface"]
    return ctx.EFI_SUCCESS

@dxeapi(params={
    "Handle": POINTER, #POINTER_T(None)
    "Protocol": GUID,
    "Interface": POINTER, #POINTER_T(None)
})
def hook_UninstallProtocolInterface(ctx, address, params):
    handle = params["Handle"]
    if handle not in ctx.ql.handle_dict:
        return ctx.EFI_NOT_FOUND
    dic = ctx.ql.handle_dict[handle]
    protocol = params["Protocol"]
    if protocol not in dic:
        return ctx.EFI_NOT_FOUND
    del dic[protocol]
    return ctx.EFI_SUCCESS

@dxeapi(params={
    "Handle": POINTER, #POINTER_T(None)
    "Protocol": GUID,
    "Interface": POINTER, #POINTER_T(POINTER_T(None))
})
def hook_HandleProtocol(ctx, address, params):
    handle = params["Handle"]
    protocol = params["Protocol"]
    interface = params['Interface']
    if handle in ctx.ql.handle_dict:
        if protocol in ctx.ql.handle_dict[handle]:
            ctx.write_int64(interface, ctx.ql.handle_dict[handle][protocol])
            return ctx.EFI_SUCCESS
    return ctx.EFI_NOT_FOUND

@dxeapi(params={
    "Protocol": GUID,
    "Event": POINTER,
    "Registration": POINTER})
def hook_RegisterProtocolNotify(ql, address, params):
    if params['Event'] in ql.loader.events:
        ql.loader.events[params['Event']]['Guid'] = params["Protocol"]
        check_and_notify_protocols(ql)
        return ql.os.ctx.EFI_SUCCESS
    return ql.os.ctx.EFI_INVALID_PARAMETER

def LocateHandles(ctx, address, params):
    handles = []
    if params["SearchKey"] == ctx.SEARCHTYPE_AllHandles:
        handles = ctx.ql.handle_dict.keys()
    elif params["SearchKey"] == ctx.SEARCHTYPE_ByProtoco:
        for handle, guid_dic in ctx.ql.handle_dict.items():
            if params["Protocol"] in guid_dic:
                handles.append(handle)
                    
    return len(handles) * pointer_size, handles

@dxeapi(params={
    "SearchType": ULONGLONG,
    "Protocol": GUID,
    "SearchKey": POINTER, #POINTER_T(None)
    "BufferSize": POINTER, #POINTER_T(ctypes.c_uint64)
    "Buffer": POINTER, #POINTER_T(POINTER_T(None))
})
def hook_LocateHandle(ctx, address, params):
    buffer_size, handles = LocateHandles(ctx, address, params)
    if len(handles) == 0:
        return ctx.EFI_NOT_FOUND
    ret = ctx.EFI_BUFFER_TOO_SMALL
    if ctx.read_int64(params["BufferSize"]) >= buffer_size:
        ptr = params["Buffer"]
        for handle in handles:
            ctx.write_int64(ptr, handle)
            ptr += pointer_size
        ret = ctx.EFI_SUCCESS
    ctx.write_int64(params["BufferSize"], buffer_size)
    return ret
    

@dxeapi(params={
    "a0": GUID,
    "a1": POINTER, #POINTER_T(POINTER_T(struct_EFI_DEVICE_PATH_PROTOCOL))
    "a2": POINTER, #POINTER_T(POINTER_T(None))
})
def hook_LocateDevicePath(ctx, address, params):
    return ctx.EFI_SUCCESS

@dxeapi(params={
    "Guid": GUID,
    "Table": POINTER, #POINTER_T(None)
})
def hook_InstallConfigurationTable(ctx, address, params):
    guid = params["Guid"]
    uuid = UUID(guid)
    efi_configuration_table = EFI_CONFIGURATION_TABLE()
    if guid in ctx.ql.efi_configuration_table:
        index = ctx.ql.efi_configuration_table.index(guid)
    else:
        index = len(ctx.ql.efi_configuration_table)
        ctx.ql.efi_configuration_table.append(guid)
    
    address = (index * ctypes.sizeof(efi_configuration_table)) + ctx.ql.efi_configuration_table_ptr
    efi_configuration_table.VendorGuid.Data1 = uuid.fields[0]
    efi_configuration_table.VendorGuid.Data2 = uuid.fields[1]
    efi_configuration_table.VendorGuid.Data3 = uuid.fields[2]
    guid_last_bytes = uuid.bytes_le[8:]
    for i in range(len(guid_last_bytes)):
        efi_configuration_table.VendorGuid.Data4[i] = guid_last_bytes[i]
    
    efi_configuration_table.VendorTable = params["Table"]
    ctx.ql.mem.write(address, convert_struct_to_bytes(efi_configuration_table))
    return ctx.EFI_SUCCESS

@dxeapi(params={
    "a0": ULONGLONG,
    "a1": POINTER, #POINTER_T(None)
    "a2": POINTER, #POINTER_T(struct_EFI_DEVICE_PATH_PROTOCOL)
    "a3": POINTER, #POINTER_T(None)
    "a4": ULONGLONG,
    "a5": POINTER, #POINTER_T(POINTER_T(None))
})
def hook_LoadImage(ctx, address, params):
    return ctx.EFI_SUCCESS

@dxeapi(params={
    "a0": POINTER, #POINTER_T(None)
    "a1": POINTER, #POINTER_T(ctypes.c_uint64)
    "a2": POINTER, #POINTER_T(POINTER_T(ctypes.c_uint16))
})
def hook_StartImage(ctx, address, params):
    return ctx.EFI_SUCCESS

@dxeapi(params={
    "a0": POINTER, #POINTER_T(None)
    "a1": ULONGLONG,
    "a2": ULONGLONG,
    "a3": POINTER, #POINTER_T(ctypes.c_uint16)
})
def hook_Exit(ctx, address, params):
    ctx.ql.nprint(f'hook_Exit')
    ctx.ql.uc.emu_stop()
    return ctx.EFI_SUCCESS

@dxeapi(params={
    "a0": POINTER, #POINTER_T(None)
})
def hook_UnloadImage(ctx, address, params):
    return ctx.EFI_SUCCESS

@dxeapi(params={
    "a0": POINTER, #POINTER_T(None)
    "a1": ULONGLONG,
})
def hook_ExitBootServices(ctx, address, params):
    ctx.ql.nprint(f'hook_ExitBootServices')
    ctx.ql.uc.emu_stop()
    return ctx.EFI_SUCCESS

@dxeapi(params={
    "Count": POINTER, #POINTER_T(ctypes.c_uint64)
})
def hook_GetNextMonotonicCount(ctx, address, params):
    ctx.ql.monotonic_count += 1
    ctx.write_int64(params["Count"], ctx.ql.monotonic_count)
    return ctx.EFI_SUCCESS

@dxeapi(params={
    "a0": ULONGLONG,
})
def hook_Stall(ctx, address, params):
    return ctx.EFI_SUCCESS

@dxeapi(params={
    "a0": ULONGLONG,
    "a1": ULONGLONG,
    "a2": ULONGLONG,
    "a3": POINTER, #POINTER_T(ctypes.c_uint16)
})
def hook_SetWatchdogTimer(ctx, address, params):
    return ctx.EFI_SUCCESS

@dxeapi(params={
    "a0": POINTER, #POINTER_T(None)
    "a1": POINTER, #POINTER_T(POINTER_T(None))
    "a2": POINTER, #POINTER_T(struct_EFI_DEVICE_PATH_PROTOCOL)
    "a3": ULONGLONG,
})
def hook_ConnectController(ctx, address, params):
    return ctx.EFI_SUCCESS

@dxeapi(params={
    "a0": POINTER, #POINTER_T(None)
    "a1": POINTER, #POINTER_T(None)
    "a2": POINTER, #POINTER_T(None)
})
def hook_DisconnectController(ctx, address, params):
    return ctx.EFI_SUCCESS

@dxeapi(params={
    "Handle": POINTER, #POINTER_T(None)
    "Protocol": GUID,
    "Interface": POINTER, #POINTER_T(POINTER_T(None))
    "AgentHandle": POINTER, #POINTER_T(None)
    "ControllerHandle": POINTER, #POINTER_T(None)
    "Attributes": UINT,
})
def hook_OpenProtocol(ctx, address, params):
    return LocateProtocol(ctx, address, params)

@dxeapi(params={
    "Handle": POINTER, #POINTER_T(None)
    "Protocol": GUID,
    "AgentHandle": POINTER, #POINTER_T(None)
    "ControllerHandle": POINTER, #POINTER_T(None)
})
def hook_CloseProtocol(ctx, address, params):
    return ctx.EFI_SUCCESS

@dxeapi(params={
    "Handle": POINTER, #POINTER_T(None)
    "Protocol": GUID,
    "EntryBuffer": POINTER, #POINTER_T(POINTER_T(struct_EFI_OPEN_PROTOCOL_INFORMATION_ENTRY))
    "EntryCount": POINTER, #POINTER_T(ctypes.c_uint64)
})
def hook_OpenProtocolInformation(ctx, address, params):
    return ctx.EFI_NOT_FOUND

@dxeapi(params={
    "a0": POINTER, #POINTER_T(None)
    "a1": GUID,
    "a2": POINTER, #POINTER_T(ctypes.c_uint64)
})
def hook_ProtocolsPerHandle(ctx, address, params):
    return ctx.EFI_SUCCESS

@dxeapi(params={
    "SearchType": ULONGLONG,
    "Protocol": GUID,
    "SearchKey": POINTER, #POINTER_T(None)
    "NoHandles": POINTER, #POINTER_T(ctypes.c_uint64)
    "Buffer": POINTER, #POINTER_T(POINTER_T(POINTER_T(None)))
})
def hook_LocateHandleBuffer(ctx, address, params):
    buffer_size, handles = LocateHandles(ctx, address, params)
    ctx.write_int64(params["NoHandles"], len(handles))
    if len(handles) == 0:
        return ctx.EFI_NOT_FOUND
    address = ctx.ql.heap.mem_alloc(buffer_size)
    ctx.write_int64(params["Buffer"], address)
    for handle in handles:
            ctx.write_int64(address, handle)
            address += pointer_size
    return ctx.EFI_SUCCESS

def LocateProtocol(ctx, address, params):
    protocol = params['Protocol']
    for handle, guid_dic in ctx.ql.handle_dict.items():
        if "Handle" in params and params["Handle"] != handle:
            continue
        if protocol in guid_dic:
            ctx.write_int64(params['Interface'], guid_dic[protocol])
            return ctx.EFI_SUCCESS
    return ctx.EFI_NOT_FOUND

@dxeapi(params={
    "Protocol": GUID,
    "Registration": POINTER, #POINTER_T(None)
    "Interface": POINTER, #POINTER_T(POINTER_T(None))
})
def hook_LocateProtocol(ctx, address, params):
    return LocateProtocol(ctx, address, params)


@dxeapi(params={
    "Handle": POINTER})
def hook_InstallMultipleProtocolInterfaces(ql, address, params):
    handle = params["Handle"]
    ql.nprint(f'hook_InstallMultipleProtocolInterfaces {handle:x}')
    dic = {}
    if handle in ql.loader.handle_dict:
        dic = ql.loader.handle_dict[handle]
    
    index = 1
    while _get_param_by_index(ql, index) != 0:
        GUID_ptr = _get_param_by_index(ql, index)
        protocol_ptr = _get_param_by_index(ql, index+1)
        GUID = str(read_guid(ql, GUID_ptr))
        ql.nprint(f'\t {GUID}, {protocol_ptr:x}')
        dic[GUID] = protocol_ptr
        index +=2
    ql.loader.handle_dict[handle] = dic
    check_and_notify_protocols(ql)
    return ql.os.ctx.EFI_SUCCESS

@dxeapi(params={
    "Handle": POINTER, #POINTER_T(None)
})
def hook_UninstallMultipleProtocolInterfaces(ql, ctx, address, params):
    handle = params["Handle"]
    ql.nprint(f'hook_UninstallMultipleProtocolInterfaces {handle:x}')
    if handle not in ctx.ql.handle_dict:
        return ctx.EFI_NOT_FOUND
    index = 1
    while _get_param_by_index(ctx, index) != 0:
        GUID_ptr = _get_param_by_index(ctx, index)
        protocol_ptr = _get_param_by_index(ctx, index+1)
        GUID = str(read_guid(ctx.ql, GUID_ptr))
        ql.nprint(f'\t {GUID}, {protocol_ptr:x}')
        dic = ctx.ql.handle_dict[handle]
        protocol = params["Protocol"]
        if protocol not in dic:
            return ctx.EFI_INVALID_PARAMETER
        del dic[protocol]
        index +=2
    return ctx.EFI_SUCCESS

@dxeapi(params={
    "Data": POINTER, #POINTER_T(None)
    "DataSize": ULONGLONG,
    "Crc32": POINTER, #POINTER_T(ctypes.c_uint32)
})
def hook_CalculateCrc32(ql, ctx, address, params):
    data = bytes(ql.mem.read(params['Data'], params['DataSize']))
    ctx.write_int32(params['Crc32'], crc32(data))
    return ctx.EFI_SUCCESS

@dxeapi(params={
    "Destination": POINTER, #POINTER_T(None)
    "Source": POINTER, #POINTER_T(None)
    "Length": ULONGLONG,
})
def hook_CopyMem(ql, ctx, address, params):
    data = bytes(ql.mem.read(params['Source'], params['Length']))
    ql.mem.write(params['Destination'], data)
    return params['Destination']

@dxeapi(params={
    "Buffer": POINTER, #POINTER_T(None)
    "Size": ULONGLONG,
    "Value": BYTE,
})
def hook_SetMem(ql, ctx, address, params):
    ptr = params["Buffer"]
    value = struct.pack('B',params["Value"])
    for i in range(0, params["Size"]):
        ql.mem.write(ptr, value)
    return ctx.EFI_SUCCESS

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


def check_and_notify_protocols(ql):
    for handle in ql.loader.handle_dict:
        for protocol in ql.loader.handle_dict[handle]:
            for event_id, event_dic in ql.loader.events.items():
                if event_dic["Guid"] == protocol:
                    SignalEvent(ql, event_id)


def CreateEvent(ql, address, params):
    event_id = len(ql.loader.events)
    event_dic = {"NotifyFunction": params["NotifyFunction"], "NotifyContext": params["NotifyContext"], "Guid": "", "Set": False}
    if "EventGroup" in params:
        event_dic["EventGroup"] =  params["EventGroup"]
    
    ql.loader.events[event_id] = event_dic
    ql.os.ctx.write_int64(params["Event"], event_id)
    return event_id

def hook_EFI_BOOT_SERVICES(ql, start_ptr):
    ql.os.monotonic_count = 0

    efi_boot_services = EFI_BOOT_SERVICES()
    ptr = start_ptr
    efi_boot_services.RaiseTPL = ptr
    ql.hook_address(hook_RaiseTPL, ptr)
    ptr += pointer_size
    efi_boot_services.RestoreTPL = ptr
    ql.hook_address(hook_RestoreTPL, ptr)
    ptr += pointer_size
    efi_boot_services.AllocatePages = ptr
    ql.hook_address(hook_AllocatePages, ptr)
    ptr += pointer_size
    efi_boot_services.FreePages = ptr
    ql.hook_address(hook_FreePages, ptr)
    ptr += pointer_size
    efi_boot_services.GetMemoryMap = ptr
    ql.hook_address(hook_GetMemoryMap, ptr)
    ptr += pointer_size
    efi_boot_services.AllocatePool = ptr
    ql.hook_address(hook_AllocatePool, ptr)
    ptr += pointer_size
    efi_boot_services.FreePool = ptr
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
    ql.hook_address(hook_InstallProtocolInterface, ptr)
    ptr += pointer_size
    efi_boot_services.ReinstallProtocolInterface = ptr
    ql.hook_address(hook_ReinstallProtocolInterface, ptr)
    ptr += pointer_size
    efi_boot_services.UninstallProtocolInterface = ptr
    ql.hook_address(hook_UninstallProtocolInterface, ptr)
    ptr += pointer_size
    efi_boot_services.HandleProtocol = ptr
    ql.hook_address(hook_HandleProtocol, ptr)
    ptr += pointer_size
    efi_boot_services.RegisterProtocolNotify = ptr
    ql.hook_address(hook_RegisterProtocolNotify, ptr)
    ptr += pointer_size
    efi_boot_services.LocateHandle = ptr
    ql.hook_address(hook_LocateHandle, ptr)
    ptr += pointer_size
    efi_boot_services.LocateDevicePath = ptr
    ql.hook_address(hook_LocateDevicePath, ptr)
    ptr += pointer_size
    efi_boot_services.InstallConfigurationTable = ptr
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
    return (ptr, efi_boot_services)

