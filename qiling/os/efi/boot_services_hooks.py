from qiling.const import *
from qiling.os.efi.fncc import *
from qiling.os.efi.efi_types_64 import *
from qiling.os.windows.fncc import *
from qiling.os.windows.fncc import _get_param_by_index


@dxeapi(params={
	"a0": ULONGLONG,
})
def hook_RaiseTPL(self, address, params):
	pass

@dxeapi(params={
	"a0": ULONGLONG,
})
def hook_RestoreTPL(self, address, params):
	pass

@dxeapi(params={
	"type": ULONGLONG,
	"MemoryType": ULONGLONG,
	"Pages": ULONGLONG,
	"Memory": POINTER, #POINTER_T(ctypes.c_uint64)
})
def hook_AllocatePages(self, address, params):
	AllocateAnyPages = 0
	AllocateMaxAddress = 1
	AllocateAddress = 2
	PageSize = 4096
	if params['type'] == AllocateAddress:
		address = self.read_int(params["Memory"])
		self.ql.mem.map(address, params["Pages"]*PageSize)
	else:
		address = self.ql.heap.mem_alloc(params["Size"])
		self.write_int(params["Memory"], address)
	return address

@dxeapi(params={
	"a0": ULONGLONG,
	"a1": ULONGLONG,
})
def hook_FreePages(self, address, params):
	pass

@dxeapi(params={
	"a0": POINTER, #POINTER_T(ctypes.c_uint64)
	"a1": POINTER, #POINTER_T(struct_EFI_MEMORY_DESCRIPTOR)
	"a2": POINTER, #POINTER_T(ctypes.c_uint64)
	"a3": POINTER, #POINTER_T(ctypes.c_uint64)
	"a4": POINTER, #POINTER_T(ctypes.c_uint32)
})
def hook_GetMemoryMap(self, address, params):
	pass

@dxeapi(params={
    "PoolType": UINT,
    "Size": UINT,
    "Buffer": POINTER,
})
def hook_AllocatePool(self, address, params):
    address = self.ql.heap.mem_alloc(params["Size"])
    self.write_int(params["Buffer"], address)
    return address

@dxeapi(params={
	"a0": POINTER, #POINTER_T(None)
})
def hook_FreePool(self, address, params):
	address = params["a0"]
	self.ql.heap.mem_free(address)
	pass

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
    return event_id

@dxeapi(params={
	"a0": POINTER, #POINTER_T(None)
	"a1": ULONGLONG,
	"a2": ULONGLONG,
})
def hook_SetTimer(self, address, params):
	pass

@dxeapi(params={
	"a0": ULONGLONG,
	"a1": POINTER, #POINTER_T(POINTER_T(None))
	"a2": POINTER, #POINTER_T(ctypes.c_uint64)
})
def hook_WaitForEvent(self, address, params):
	pass

@dxeapi(params={
	"a0": POINTER, #POINTER_T(None)
})
def hook_SignalEvent(self, address, params):
	pass

@dxeapi(params={
	"a0": POINTER, #POINTER_T(None)
})
def hook_CloseEvent(self, address, params):
	self.ql.events.remove(params['a0'])
	pass

@dxeapi(params={
	"a0": POINTER, #POINTER_T(None)
})
def hook_CheckEvent(self, address, params):
	pass

@dxeapi(params={
	"a0": POINTER, #POINTER_T(POINTER_T(None))
	"a1": GUID,
	"a2": ULONGLONG,
	"a3": POINTER, #POINTER_T(None)
})
def hook_InstallProtocolInterface(self, address, params):
	pass

@dxeapi(params={
	"a0": POINTER, #POINTER_T(None)
	"a1": GUID,
	"a2": POINTER, #POINTER_T(None)
	"a3": POINTER, #POINTER_T(None)
})
def hook_ReinstallProtocolInterface(self, address, params):
	pass

@dxeapi(params={
	"a0": POINTER, #POINTER_T(None)
	"a1": GUID,
	"a2": POINTER, #POINTER_T(None)
})
def hook_UninstallProtocolInterface(self, address, params):
	pass

@dxeapi(params={
	"a0": POINTER, #POINTER_T(None)
	"a1": GUID,
	"a2": POINTER, #POINTER_T(POINTER_T(None))
})
def hook_HandleProtocol(self, address, params):
	pass

@dxeapi(params={
    "Protocol": GUID,
    "Event": POINTER,
    "Registration": POINTER})
def hook_RegisterProtocolNotify(self, address, params):
    pass

@dxeapi(params={
	"a0": ULONGLONG,
	"a1": GUID,
	"a2": POINTER, #POINTER_T(None)
	"a3": POINTER, #POINTER_T(ctypes.c_uint64)
	"a4": POINTER, #POINTER_T(POINTER_T(None))
})
def hook_LocateHandle(self, address, params):
	pass

@dxeapi(params={
	"a0": GUID,
	"a1": POINTER, #POINTER_T(POINTER_T(struct_EFI_DEVICE_PATH_PROTOCOL))
	"a2": POINTER, #POINTER_T(POINTER_T(None))
})
def hook_LocateDevicePath(self, address, params):
	pass

@dxeapi(params={
	"a0": GUID,
	"a1": POINTER, #POINTER_T(None)
})
def hook_InstallConfigurationTable(self, address, params):
	pass

@dxeapi(params={
	"a0": ULONGLONG,
	"a1": POINTER, #POINTER_T(None)
	"a2": POINTER, #POINTER_T(struct_EFI_DEVICE_PATH_PROTOCOL)
	"a3": POINTER, #POINTER_T(None)
	"a4": ULONGLONG,
	"a5": POINTER, #POINTER_T(POINTER_T(None))
})
def hook_LoadImage(self, address, params):
	pass

@dxeapi(params={
	"a0": POINTER, #POINTER_T(None)
	"a1": POINTER, #POINTER_T(ctypes.c_uint64)
	"a2": POINTER, #POINTER_T(POINTER_T(ctypes.c_uint16))
})
def hook_StartImage(self, address, params):
	pass

@dxeapi(params={
	"a0": POINTER, #POINTER_T(None)
	"a1": ULONGLONG,
	"a2": ULONGLONG,
	"a3": POINTER, #POINTER_T(ctypes.c_uint16)
})
def hook_Exit(self, address, params):
	pass

@dxeapi(params={
	"a0": POINTER, #POINTER_T(None)
})
def hook_UnloadImage(self, address, params):
	pass

@dxeapi(params={
	"a0": POINTER, #POINTER_T(None)
	"a1": ULONGLONG,
})
def hook_ExitBootServices(self, address, params):
	pass

@dxeapi(params={
	"a0": POINTER, #POINTER_T(ctypes.c_uint64)
})
def hook_GetNextMonotonicCount(self, address, params):
	pass

@dxeapi(params={
	"a0": ULONGLONG,
})
def hook_Stall(self, address, params):
	pass

@dxeapi(params={
	"a0": ULONGLONG,
	"a1": ULONGLONG,
	"a2": ULONGLONG,
	"a3": POINTER, #POINTER_T(ctypes.c_uint16)
})
def hook_SetWatchdogTimer(self, address, params):
	pass

@dxeapi(params={
	"a0": POINTER, #POINTER_T(None)
	"a1": POINTER, #POINTER_T(POINTER_T(None))
	"a2": POINTER, #POINTER_T(struct_EFI_DEVICE_PATH_PROTOCOL)
	"a3": ULONGLONG,
})
def hook_ConnectController(self, address, params):
	pass

@dxeapi(params={
	"a0": POINTER, #POINTER_T(None)
	"a1": POINTER, #POINTER_T(None)
	"a2": POINTER, #POINTER_T(None)
})
def hook_DisconnectController(self, address, params):
	pass

@dxeapi(params={
	"a0": POINTER, #POINTER_T(None)
	"a1": GUID,
	"a2": POINTER, #POINTER_T(POINTER_T(None))
	"a3": POINTER, #POINTER_T(None)
	"a4": POINTER, #POINTER_T(None)
	"a5": UINT,
})
def hook_OpenProtocol(self, address, params):
	pass

@dxeapi(params={
	"a0": POINTER, #POINTER_T(None)
	"a1": GUID,
	"a2": POINTER, #POINTER_T(None)
	"a3": POINTER, #POINTER_T(None)
})
def hook_CloseProtocol(self, address, params):
	pass

@dxeapi(params={
	"a0": POINTER, #POINTER_T(None)
	"a1": GUID,
	"a2": POINTER, #POINTER_T(POINTER_T(struct_EFI_OPEN_PROTOCOL_INFORMATION_ENTRY))
	"a3": POINTER, #POINTER_T(ctypes.c_uint64)
})
def hook_OpenProtocolInformation(self, address, params):
	pass

@dxeapi(params={
	"a0": POINTER, #POINTER_T(None)
	"a1": GUID,
	"a2": POINTER, #POINTER_T(ctypes.c_uint64)
})
def hook_ProtocolsPerHandle(self, address, params):
	pass

@dxeapi(params={
	"a0": ULONGLONG,
	"a1": GUID,
	"a2": POINTER, #POINTER_T(None)
	"a3": POINTER, #POINTER_T(ctypes.c_uint64)
	"a4": POINTER, #POINTER_T(POINTER_T(POINTER_T(None)))
})
def hook_LocateHandleBuffer(self, address, params):
	pass

@dxeapi(params={
	"a0": GUID,
	"a1": POINTER, #POINTER_T(None)
	"a2": POINTER, #POINTER_T(POINTER_T(None))
})
def hook_LocateProtocol(self, address, params):
	pass

@dxeapi(params={
    "Handle": POINTER})
def hook_InstallMultipleProtocolInterfaces(self, address, params):
	handle = params["Handle"]
	print(f'hook_InstallMultipleProtocolInterfaces {handle:x}')
	dic = {}
	if handle in self.ql.handle_dict:
		dic = self.ql.handle_dict[handle]
	
	index = 1
	while _get_param_by_index(self, index) != 0:
		GUID_ptr = _get_param_by_index(self, index)
		protocol_ptr = _get_param_by_index(self, index+1)
		GUID = read_guid(self.ql, GUID_ptr)
		print(f'\t {GUID}, {protocol_ptr:x}')
		dic[GUID] = protocol_ptr
		index +=2
	self.ql.handle_dict[handle] = dic

@dxeapi(params={
	"a0": POINTER, #POINTER_T(None)
})
def hook_UninstallMultipleProtocolInterfaces(self, address, params):
	pass

@dxeapi(params={
	"a0": POINTER, #POINTER_T(None)
	"a1": ULONGLONG,
	"a2": POINTER, #POINTER_T(ctypes.c_uint32)
})
def hook_CalculateCrc32(self, address, params):
	pass

@dxeapi(params={
	"a0": POINTER, #POINTER_T(None)
	"a1": POINTER, #POINTER_T(None)
	"a2": ULONGLONG,
})
def hook_CopyMem(self, address, params):
	pass

@dxeapi(params={
	"a0": POINTER, #POINTER_T(None)
	"a1": ULONGLONG,
	"a2": ULONGLONG,
})
def hook_SetMem(self, address, params):
	pass

@dxeapi(params={
	"a0": UINT,
	"a1": ULONGLONG,
	"a2": POINTER, #POINTER_T(ctypes.CFUNCTYPE(None, POINTER_T(None), POINTER_T(None)))
	"a3": POINTER, #POINTER_T(None)
	"a4": GUID,
	"a5": POINTER, #POINTER_T(POINTER_T(None))
})
def hook_CreateEventEx(self, address, params):
	pass



def hook_EFI_BOOT_SERVICES(start_ptr, ql):
	efi_boot_services = EFI_BOOT_SERVICES()
	ptr = start_ptr
	pointer_size = 8
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

