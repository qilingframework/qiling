#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from binascii import crc32

from qiling.os.const import *
from .fncc import *
from .utils import *
from .ProcessorBind import *
from .UefiSpec import *

# TODO: find a better solution than hardcoding this
pointer_size = 8

@dxeapi(params = {
	"NewTpl" : ULONGLONG		# EFI_TPL
})
def hook_RaiseTPL(ql, address, params):
	prev_tpl = ql.loader.tpl
	ql.loader.tpl = params["NewTpl"]

	return prev_tpl

@dxeapi(params = {
	"OldTpl": ULONGLONG			# EFI_TPL
})
def hook_RestoreTPL(ql, address, params):
	ql.loader.tpl = params["OldTpl"]

@dxeapi(params = {
	"type"		: INT,			# EFI_ALLOCATE_TYPE
	"MemoryType": INT,			# EFI_MEMORY_TYPE
	"Pages"		: ULONGLONG,	# UINTN
	"Memory"	: POINTER		# PTR(EFI_PHYSICAL_ADDRESS)
})
def hook_AllocatePages(ql, address, params):
	alloc_size = params["Pages"] * PAGE_SIZE

	if params['type'] == EFI_ALLOCATE_TYPE.AllocateAddress:
		address = read_int64(ql, params["Memory"])

		# TODO: check the range [address, address + alloc_size] is available first
		ql.mem.map(address, alloc_size)
	else:
		# TODO: allocate memory according to 'MemoryType'
		address = ql.loader.dxe_context.heap.alloc(alloc_size)

		if address == 0:
			return EFI_OUT_OF_RESOURCES

		write_int64(ql, params["Memory"], address)

	return EFI_SUCCESS

@dxeapi(params = {
	"Memory"	: ULONGLONG,	# EFI_PHYSICAL_ADDRESS
	"Pages"		: ULONGLONG		# UINTN
})
def hook_FreePages(ql, address, params):
	address = params["Memory"]
	alloc_size = params["Pages"] * PAGE_SIZE

	ret = ql.mem.free(address, alloc_size)

	return EFI_SUCCESS if ret else EFI_INVALID_PARAMETER

@dxeapi(params = {
	"MemoryMapSize"		: POINTER,	# PTR(UINTN)
	"MemoryMap"			: POINTER,	# PTR(EFI_MEMORY_DESCRIPTOR)
	"MapKey"			: POINTER,	# PTR(UINTN)
	"DescriptorSize"	: POINTER,	# PTR(UINTN)
	"DescriptorVersion"	: POINTER	# PTR(UINT32)
})
def hook_GetMemoryMap(ql, address, params):
	return EFI_SUCCESS

@dxeapi(params = {
	"PoolType"	: INT,		# EFI_MEMORY_TYPE
	"Size"		: INT,		# UINTN
	"Buffer"	: POINTER	# PTR(PTR(VOID))
})
def hook_AllocatePool(ql, address, params):
	# TODO: allocate memory acording to "PoolType"
	address = ql.loader.dxe_context.heap.alloc(params["Size"])
	write_int64(ql, params["Buffer"], address)

	return EFI_SUCCESS if address else EFI_OUT_OF_RESOURCES

@dxeapi(params = {
	"Buffer": POINTER # PTR(VOID)
})
def hook_FreePool(ql, address, params):
	address = params["Buffer"]
	ret = ql.loader.dxe_context.heap.free(address)

	return EFI_SUCCESS if ret else EFI_INVALID_PARAMETER

@dxeapi(params = {
	"Type"			: UINT,		# UINT32
	"NotifyTpl"		: UINT,		# EFI_TPL
	"NotifyFunction": POINTER,	# EFI_EVENT_NOTIFY
	"NotifyContext"	: POINTER,	# PTR(VOID)
	"Event"			: POINTER	# PTR(EFI_EVENT)
})
def hook_CreateEvent(ql, address, params):
	return CreateEvent(ql, params)

@dxeapi(params = {
	"Event"			: POINTER,		# EFI_EVENT
	"Type"			: ULONGLONG,	# EFI_TIMER_DELAY
	"TriggerTime"	: ULONGLONG		# UINT64
})
def hook_SetTimer(ql, address, params):
	return EFI_SUCCESS

@dxeapi(params = {
	"NumberOfEvents": ULONGLONG,	# UINTN
	"Event"			: POINTER,		# PTR(EFI_EVENT)
	"Index"			: POINTER,		# PTR(UINTN)
})
def hook_WaitForEvent(ql, address, params):
	return EFI_SUCCESS

@dxeapi(params = {
	"Event": POINTER # EFI_EVENT
})
def hook_SignalEvent(ql, address, params):
	event_id = params["Event"]

	if event_id in ql.loader.events:
		event = ql.loader.events[event_id]

		if not event["Set"]:
			event["Set"] = True
			notify_func = event["NotifyFunction"]
			notify_context = event["NotifyContext"]
			ql.loader.notify_list.append((event_id, notify_func, notify_context))

		return EFI_SUCCESS
	else:
		return EFI_INVALID_PARAMETER

@dxeapi(params = {
	"Event": POINTER # EFI_EVENT
})
def hook_CloseEvent(ql, address, params):
	event_id = params["Event"]
	del ql.loader.events[event_id]

	return EFI_SUCCESS

@dxeapi(params = {
	"Event": POINTER # EFI_EVENT
})
def hook_CheckEvent(ql, address, params):
	event_id = params["Event"]

	return EFI_SUCCESS if ql.loader.events[event_id]["Set"] else EFI_NOT_READY

@dxeapi(params = {
	"Handle"		: POINTER,		# PTR(EFI_HANDLE)
	"Protocol"		: GUID,			# PTR(EFI_GUID)
	"InterfaceType"	: ULONGLONG,	# EFI_INTERFACE_TYPE
	"Interface"		: POINTER,		# PTR(VOID)
})
def hook_InstallProtocolInterface(ql, address, params):
	handle = read_int64(ql, params["Handle"])

	if handle == 0:
		handle = ql.loader.dxe_context.heap.alloc(1)

	dic = ql.loader.dxe_context.protocols.get(handle, {})

	dic[params["Protocol"]] = params["Interface"]
	ql.loader.dxe_context.protocols[handle] = dic
	check_and_notify_protocols(ql)
	write_int64(ql, params["Handle"], handle)

	return EFI_SUCCESS

@dxeapi(params = {
	"Handle"		: POINTER,	# EFI_HANDLE
	"Protocol"		: GUID,		# PTR(EFI_GUID)
	"OldInterface"	: POINTER,	# PTR(VOID)
	"NewInterface"	: POINTER,	# PTR(VOID)
})
def hook_ReinstallProtocolInterface(ql, address, params):
	handle = params["Handle"]

	if handle not in ql.loader.dxe_context.protocols:
		return EFI_NOT_FOUND

	dic = ql.loader.dxe_context.protocols[handle]
	protocol = params["Protocol"]

	if protocol not in dic:
		return EFI_NOT_FOUND

	dic[protocol] = params["NewInterface"]

	return EFI_SUCCESS

@dxeapi(params = {
	"Handle"	: POINTER,	# EFI_HANDLE
	"Protocol"	: GUID,		# PTR(EFI_GUID)
	"Interface"	: POINTER	# PTR(VOID)
})
def hook_UninstallProtocolInterface(ql, address, params):
	handle = params["Handle"]

	if handle not in ql.loader.dxe_context.protocols:
		return EFI_NOT_FOUND

	dic = ql.loader.dxe_context.protocols[handle]
	protocol = params["Protocol"]

	if protocol not in dic:
		return EFI_NOT_FOUND

	del dic[protocol]

	return EFI_SUCCESS

@dxeapi(params = {
	"Handle"	: POINTER,	# EFI_HANDLE
	"Protocol"	: GUID,		# PTR(EFI_GUID)
	"Interface"	: POINTER	# PTR(PTR(VOID))
})
def hook_HandleProtocol(ql, address, params):
	handle = params["Handle"]
	protocol = params["Protocol"]
	interface = params['Interface']

	hdict = ql.loader.dxe_context.protocols

	if handle in hdict and protocol in hdict[handle]:
		write_int64(ql, interface, hdict[handle][protocol])

	return EFI_NOT_FOUND

@dxeapi(params = {
	"Protocol"		: GUID,		# PTR(EFI_GUID)
	"Event"			: POINTER,	# EFI_EVENT
	"Registration"	: POINTER	# PTR(PTR(VOID))
})
def hook_RegisterProtocolNotify(ql, address, params):
	event = params['Event']
	proto = params["Protocol"]

	if event in ql.loader.events:
		ql.loader.events[event]['Guid'] = proto
		check_and_notify_protocols(ql)

		return EFI_SUCCESS

	return EFI_INVALID_PARAMETER

@dxeapi(params = {
	"SearchType": INT,		# EFI_LOCATE_SEARCH_TYPE
	"Protocol"	: GUID,		# PTR(EFI_GUID)
	"SearchKey"	: POINTER,	# PTR(VOID)
	"BufferSize": POINTER,	# PTR(UINTN)
	"Buffer"	: POINTER	# PTR(EFI_HANDLE)
})
def hook_LocateHandle(ql, address, params):
	buffer_size, handles = LocateHandles(ql.loader.dxe_context, params)

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

@dxeapi(params = {
	"Protocol"	: GUID,		# PTR(EFI_GUID)
	"DevicePath": POINTER,	# PTR(PTR(EFI_DEVICE_PATH_PROTOCOL))
	"Device"	: POINTER	# PTR(EFI_HANDLE)
})
def hook_LocateDevicePath(ql, address, params):
	return EFI_SUCCESS

@dxeapi(params = {
	"Guid"	: GUID,		# PTR(EFI_GUID)
	"Table"	: POINTER	# PTR(VOID)
})
def hook_InstallConfigurationTable(ql, address, params):
	guid = params["Guid"]
	table = params["Table"]

	return CoreInstallConfigurationTable(ql, guid, table)

@dxeapi(params = {
	"BootPolicy"		: BOOL,			# BOOLEAN
	"ParentImageHandle"	: POINTER,		# EFI_HANDLE
	"DevicePath"		: POINTER,		# PTR(EFI_DEVICE_PATH_PROTOCOL)
	"SourceBuffer"		: POINTER,		# PTR(VOID)
	"SourceSize"		: ULONGLONG,	# UINTN
	"ImageHandle"		: POINTER		# PTR(EFI_HANDLE)
})
def hook_LoadImage(ql, address, params):
	return EFI_SUCCESS

@dxeapi(params = {
	"ImageHandle"	: POINTER,	# EFI_HANDLE
	"ExitDataSize"	: POINTER,	# PTR(UINTN)
	"ExitData"		: POINTER	# PTR(PTR(CHAR16))
})
def hook_StartImage(ql, address, params):
	return EFI_SUCCESS

@dxeapi(params = {
	"ImageHandle"	: POINTER,		# EFI_HANDLE
	"ExitStatus"	: ULONGLONG,	# EFI_STATUS
	"ExitDataSize"	: ULONGLONG,	# UINTN
	"ExitData"		: POINTER		# PTR(CHAR16)
})
def hook_Exit(ql, address, params):
	ql.uc.emu_stop()

	return EFI_SUCCESS

@dxeapi(params = {
	"ImageHandle" : POINTER # EFI_HANDLE
})
def hook_UnloadImage(ql, address, params):
	return EFI_SUCCESS

@dxeapi(params = {
	"ImageHandle"	: POINTER,	# EFI_HANDLE
	"MapKey"		: ULONGLONG	# UINTN
})
def hook_ExitBootServices(ql, address, params):
	ql.uc.emu_stop()

	return EFI_SUCCESS

@dxeapi(params = {
	"Count": POINTER # PTR(UINT64)
})
def hook_GetNextMonotonicCount(ql, address, params):
	out = params["Count"]

	ql.os.monotonic_count += 1
	write_int64(ql, out, ql.os.monotonic_count)

	return EFI_SUCCESS

@dxeapi(params = {
	"Microseconds": ULONGLONG # UINTN
})
def hook_Stall(ql, address, params):
	return EFI_SUCCESS

@dxeapi(params = {
	"Timeout"		: ULONGLONG,	# UINTN
	"WatchdogCode"	: ULONGLONG,	# UINT64
	"DataSize"		: ULONGLONG,	# UINTN
	"WatchdogData"	: POINTER		# PTR(CHAR16)
})
def hook_SetWatchdogTimer(ql, address, params):
	return EFI_SUCCESS

@dxeapi(params = {
	"ControllerHandle"		: POINTER,	# EFI_HANDLE
	"DriverImageHandle"		: POINTER,	#PTR(EFI_HANDLE)
	"RemainingDevicePath"	: POINTER,	# PTR(EFI_DEVICE_PATH_PROTOCOL)
	"Recursive"				: BOOL		# BOOLEAN
})
def hook_ConnectController(ql, address, params):
	return EFI_SUCCESS

@dxeapi(params = {
	"ControllerHandle"	: POINTER,	# EFI_HANDLE
	"DriverImageHandle"	: POINTER,	# EFI_HANDLE
	"ChildHandle"		: POINTER	# EFI_HANDLE
})
def hook_DisconnectController(ql, address, params):
	return EFI_SUCCESS

@dxeapi(params = {
	"Handle"			: POINTER,	# EFI_HANDLE
	"Protocol"			: GUID,		# PTR(EFI_GUID)
	"Interface"			: POINTER,	# PTR(PTR(VOID))
	"AgentHandle"		: POINTER,	# EFI_HANDLE
	"ControllerHandle"	: POINTER,	# EFI_HANDLE
	"Attributes"		: UINT		# UINT32
})
def hook_OpenProtocol(ql, address, params):
	return LocateProtocol(ql.loader.dxe_context, params)

@dxeapi(params = {
	"Handle"			: POINTER,	# EFI_HANDLE
	"Protocol"			: GUID,		# PTR(EFI_GUID)
	"AgentHandle"		: POINTER,	# EFI_HANDLE
	"ControllerHandle"	: POINTER	# EFI_HANDLE
})
def hook_CloseProtocol(ql, address, params):
	return EFI_SUCCESS

@dxeapi(params = {
	"Handle"		: POINTER,	# EFI_HANDLE
	"Protocol"		: GUID,		# PTR(EFI_GUID)
	"EntryBuffer"	: POINTER,	# PTR(PTR(EFI_OPEN_PROTOCOL_INFORMATION_ENTRY))
	"EntryCount"	: POINTER	# PTR(UINTN)
})
def hook_OpenProtocolInformation(ql, address, params):
	return EFI_NOT_FOUND

@dxeapi(params = {
	"Handle"				: POINTER,	# EFI_HANDLE
	"ProtocolBuffer"		: POINTER,	# PTR(PTR(PTR(EFI_GUID)))
	"ProtocolBufferCount"	: POINTER	# PTR(UINTN)
})
def hook_ProtocolsPerHandle(ql, address, params):
	return EFI_SUCCESS

@dxeapi(params = {
	"SearchType": INT,		# EFI_LOCATE_SEARCH_TYPE
	"Protocol"	: GUID,		# PTR(EFI_GUID)
	"SearchKey"	: POINTER,	# PTR(VOID)
	"NoHandles"	: POINTER,	# PTR(UINTN)
	"Buffer"	: POINTER	# PTR(PTR(EFI_HANDLE))
})
def hook_LocateHandleBuffer(ql, address, params):
	buffer_size, handles = LocateHandles(ql.loader.dxe_context, params)
	write_int64(ql, params["NoHandles"], len(handles))

	if len(handles) == 0:
		return EFI_NOT_FOUND

	address = ql.loader.dxe_context.heap.alloc(buffer_size)
	write_int64(ql, params["Buffer"], address)

	if address == 0:
		return EFI_OUT_OF_RESOURCES

	for handle in handles:
		write_int64(ql, address, handle)
		address += pointer_size

	return EFI_SUCCESS

@dxeapi(params = {
	"Protocol"		: GUID,		# PTR(EFI_GUID)
	"Registration"	: POINTER,	# PTR(VOID)
	"Interface"		: POINTER	# PTR(PTR(VOID))
})
def hook_LocateProtocol(ql, address, params):
	return LocateProtocol(ql.loader.dxe_context, params)

@dxeapi(params = {
	"Handle" : POINTER # PTR(EFI_HANDLE)
	# ...
})
def hook_InstallMultipleProtocolInterfaces(ql, address, params):
	handle = read_int64(ql, params["Handle"])

	if handle == 0:
		handle = ql.loader.dxe_context.heap.alloc(1)

	dic = ql.loader.dxe_context.protocols.get(handle, {})

	# process elipsiss arguments
	index = 1
	while ql.os.get_param_by_index(index) != 0:
		GUID_ptr = ql.os.get_param_by_index(index)
		protocol_ptr = ql.os.get_param_by_index(index+1)
		GUID = str(ql.os.read_guid(GUID_ptr))
		logging.info(f' | {GUID} {protocol_ptr:x}')
		dic[GUID] = protocol_ptr
		index +=2

	ql.loader.dxe_context.protocols[handle] = dic
	check_and_notify_protocols(ql)
	write_int64(ql, params["Handle"], handle)

	return EFI_SUCCESS

@dxeapi(params = {
	"Handle" : POINTER # EFI_HANDLE
	# ...
})
def hook_UninstallMultipleProtocolInterfaces(ql, address, params):
	handle = params["Handle"]

	if handle not in ql.loader.dxe_context.protocols:
		return EFI_NOT_FOUND

	dic = ql.loader.dxe_context.protocols[handle]

	# process elipsiss arguments
	index = 1
	while ql.os.get_param_by_index(index) != 0:
		GUID_ptr = ql.os.get_param_by_index(index)
		protocol_ptr = ql.os.get_param_by_index(index+1)
		GUID = str(ql.os.read_guid(GUID_ptr))
		logging.info(f' | {GUID}, {protocol_ptr:x}')

		if GUID not in dic:
			return EFI_INVALID_PARAMETER

		del dic[GUID]
		index +=2

	return EFI_SUCCESS

@dxeapi(params = {
	"Data"		: POINTER,		# PTR(VOID)
	"DataSize"	: ULONGLONG,	# UINTN
	"Crc32"		: POINTER		# PTR(UINT32)
})
def hook_CalculateCrc32(ql, address, params):
	data = bytes(ql.mem.read(params['Data'], params['DataSize']))
	write_int32(ql, params['Crc32'], crc32(data))

	return EFI_SUCCESS

@dxeapi(params = {
	"Destination"	: POINTER,	# PTR(VOID)
	"Source"		: POINTER,	# PTR(VOID)
	"Length"		: SIZE_T	# UINTN
})
def hook_CopyMem(ql, address, params):
	data = bytes(ql.mem.read(params['Source'], params['Length']))
	ql.mem.write(params['Destination'], data)

@dxeapi(params = {
	"Buffer": POINTER,	# PTR(VOID)
	"Size"	: SIZE_T,	# UINTN
	"Value"	: BYTE		# UINT8
})
def hook_SetMem(ql, address, params):
	ptr = params["Buffer"]
	value = struct.pack('B',params["Value"] & 0xff)

	# TODO: do this the Pythonic way
	for i in range(params["Size"]):
		ql.mem.write(ptr + i, value)

@dxeapi(params = {
	"Type"			: UINT,		# UINT32
	"NotifyTpl"		: ULONGLONG,# EFI_TPL
	"NotifyFunction": POINTER,	# EFI_EVENT_NOTIFY
	"NotifyContext"	: POINTER,	# PTR(VOID)
	"EventGroup"	: GUID,		# PTR(EFI_GUID)
	"Event"			: POINTER	# PTR(EFI_EVENT)
})
def hook_CreateEventEx(ql, address, params):
	return CreateEvent(ql, params)

def CreateEvent(ql, params):
	event_id = len(ql.loader.events)
	event_dic = {
		"NotifyFunction": params["NotifyFunction"],
		"NotifyContext"	: params["NotifyContext"],
		"Guid"			: "",
		"Set"			: False
	}

	if "EventGroup" in params:
		event_dic["EventGroup"] = params["EventGroup"]

	ql.loader.events[event_id] = event_dic
	write_int64(ql, params["Event"], event_id)

	return EFI_SUCCESS

def initialize(ql, gBS : int):
	descriptor = {
		'struct' : EFI_BOOT_SERVICES,
		'fields' : (
			('Hdr',							None),
			('RaiseTPL',					hook_RaiseTPL),
			('RestoreTPL',					hook_RestoreTPL),
			('AllocatePages',				hook_AllocatePages),
			('FreePages',					hook_FreePages),
			('GetMemoryMap',				hook_GetMemoryMap),
			('AllocatePool',				hook_AllocatePool),
			('FreePool',					hook_FreePool),
			('CreateEvent',					hook_CreateEvent),
			('SetTimer',					hook_SetTimer),
			('WaitForEvent',				hook_WaitForEvent),
			('SignalEvent',					hook_SignalEvent),
			('CloseEvent',					hook_CloseEvent),
			('CheckEvent',					hook_CheckEvent),
			('InstallProtocolInterface',	hook_InstallProtocolInterface),
			('ReinstallProtocolInterface',	hook_ReinstallProtocolInterface),
			('UninstallProtocolInterface',	hook_UninstallProtocolInterface),
			('HandleProtocol',				hook_HandleProtocol),
			('Reserved',					None),
			('RegisterProtocolNotify',		hook_RegisterProtocolNotify),
			('LocateHandle',				hook_LocateHandle),
			('LocateDevicePath',			hook_LocateDevicePath),
			('InstallConfigurationTable',	hook_InstallConfigurationTable),
			('LoadImage',					hook_LoadImage),
			('StartImage',					hook_StartImage),
			('Exit',						hook_Exit),
			('UnloadImage',					hook_UnloadImage),
			('ExitBootServices',			hook_ExitBootServices),
			('GetNextMonotonicCount',		hook_GetNextMonotonicCount),
			('Stall',						hook_Stall),
			('SetWatchdogTimer',			hook_SetWatchdogTimer),
			('ConnectController',			hook_ConnectController),
			('DisconnectController',		hook_DisconnectController),
			('OpenProtocol',				hook_OpenProtocol),
			('CloseProtocol',				hook_CloseProtocol),
			('OpenProtocolInformation',		hook_OpenProtocolInformation),
			('ProtocolsPerHandle',			hook_ProtocolsPerHandle),
			('LocateHandleBuffer',			hook_LocateHandleBuffer),
			('LocateProtocol',				hook_LocateProtocol),
			('InstallMultipleProtocolInterfaces',	hook_InstallMultipleProtocolInterfaces),
			('UninstallMultipleProtocolInterfaces',	hook_UninstallMultipleProtocolInterfaces),
			('CalculateCrc32',				hook_CalculateCrc32),
			('CopyMem',						hook_CopyMem),
			('SetMem',						hook_SetMem),
			('CreateEventEx',				hook_CreateEventEx)
		)
	}

	ql.os.monotonic_count = 0

	instance = init_struct(ql, gBS, descriptor)
	instance.saveTo(ql, gBS)

__all__ = [
	'initialize'
]