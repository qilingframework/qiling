#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.const import *
from qiling.os.const import *

from qiling.os.uefi.const import EFI_SUCCESS, EFI_NOT_FOUND, EFI_OUT_OF_RESOURCES, EFI_INVALID_PARAMETER
from qiling.os.uefi.utils import *
from qiling.os.uefi.fncc import *
from qiling.os.uefi.ProcessorBind import *
from qiling.os.uefi.UefiBaseType import *
from qiling.os.uefi.UefiMultiPhase import *
from qiling.os.uefi.UefiSpec import *
from qiling.os.uefi.protocols import common
from qiling.os.uefi import rt

# @see: MdePkg\Include\Pi\PiSmmCis.h

class EFI_MM_IO_WIDTH(ENUM):
	_members_ = [
		'MM_IO_UINT8',
		'MM_IO_UINT16',
		'MM_IO_UINT32',
		'MM_IO_UINT64'
	]

EFI_MM_HANDLER_ENTRY_POINT = FUNCPTR(EFI_STATUS, EFI_HANDLE, PTR(VOID), PTR(VOID), PTR(UINTN))
EFI_MM_NOTIFY_FN = FUNCPTR(EFI_STATUS, PTR(EFI_GUID), PTR(VOID), EFI_HANDLE)

class EFI_MM_IO_ACCESS(STRUCT):
	EFI_SMM_CPU_IO2_PROTOCOL = STRUCT

	_fields_ = [
		('Read',	FUNCPTR(EFI_STATUS, PTR(EFI_SMM_CPU_IO2_PROTOCOL), EFI_MM_IO_WIDTH, UINT64, UINTN, PTR(VOID))),
		('Write',	FUNCPTR(EFI_STATUS, PTR(EFI_SMM_CPU_IO2_PROTOCOL), EFI_MM_IO_WIDTH, UINT64, UINTN, PTR(VOID))),
	]

class EFI_SMM_CPU_IO2_PROTOCOL(STRUCT):
	_fields_ = [
		('Mem',	EFI_MM_IO_ACCESS),
		('Io',	EFI_MM_IO_ACCESS)
	]

class EFI_SMM_SYSTEM_TABLE2(STRUCT):
	EFI_SMM_SYSTEM_TABLE2 = STRUCT
	_pack_ = 8

	_fields_ = [
		('Hdr',								EFI_TABLE_HEADER),
		('SmmFirmwareVendor',				PTR(CHAR16)),
		('SmmFirmwareRevision',				UINT32),
		('SmmInstallConfigurationTable',	FUNCPTR(EFI_STATUS, PTR(EFI_SMM_SYSTEM_TABLE2), PTR(EFI_GUID), PTR(VOID), UINTN)),
		('SmmIo',							EFI_SMM_CPU_IO2_PROTOCOL),
		('SmmAllocatePool',					FUNCPTR(EFI_STATUS, EFI_MEMORY_TYPE, UINTN, PTR(PTR(VOID)))),
		('SmmFreePool',						FUNCPTR(EFI_STATUS, PTR(VOID))),
		('SmmAllocatePages',				FUNCPTR(EFI_STATUS, EFI_ALLOCATE_TYPE, EFI_MEMORY_TYPE, UINTN, PTR(EFI_PHYSICAL_ADDRESS))),
		('SmmFreePages',					FUNCPTR(EFI_STATUS, EFI_PHYSICAL_ADDRESS, UINTN)),
		('SmmStartupThisAp',				FUNCPTR(EFI_STATUS, FUNCPTR(VOID, PTR(VOID)), UINTN, PTR(VOID))),
		('CurrentlyExecutingCpu',			UINTN),
		('NumberOfCpus',					UINTN),
		('CpuSaveStateSize',				PTR(UINTN)),
		('CpuSaveState',					PTR(PTR(VOID))),
		('NumberOfTableEntries',			UINTN),
		('SmmConfigurationTable',			PTR(EFI_CONFIGURATION_TABLE)),
		('SmmInstallProtocolInterface',		FUNCPTR(EFI_STATUS, PTR(EFI_HANDLE), PTR(EFI_GUID), EFI_INTERFACE_TYPE, PTR(VOID))),
		('SmmUninstallProtocolInterface',	FUNCPTR(EFI_STATUS, PTR(VOID), PTR(EFI_GUID), PTR(VOID))),
		('SmmHandleProtocol',				FUNCPTR(EFI_STATUS, PTR(VOID), PTR(EFI_GUID), PTR(PTR(VOID)))),
		('SmmRegisterProtocolNotify',		FUNCPTR(EFI_STATUS, PTR(EFI_GUID), EFI_MM_NOTIFY_FN, PTR(PTR(VOID)))),
		('SmmLocateHandle',					FUNCPTR(EFI_STATUS, EFI_LOCATE_SEARCH_TYPE, PTR(EFI_GUID), PTR(VOID), PTR(UINTN), PTR(EFI_HANDLE))),
		('SmmLocateProtocol',				FUNCPTR(EFI_STATUS, PTR(EFI_GUID), PTR(VOID), PTR(PTR(VOID)))),
		('SmiManage',						FUNCPTR(EFI_STATUS, PTR(EFI_GUID), PTR(VOID), PTR(VOID), PTR(UINTN))),
		('SmiHandlerRegister',				FUNCPTR(EFI_STATUS, EFI_MM_HANDLER_ENTRY_POINT, PTR(EFI_GUID), PTR(EFI_HANDLE))),
		('SmiHandlerUnRegister',			FUNCPTR(EFI_STATUS, EFI_HANDLE)),
	]

@dxeapi(params = {
	"Guid"	: GUID,		# PTR(EFI_GUID)
	"Table"	: POINTER	# PTR(VOID)
})
def hook_SmmInstallConfigurationTable(ql: Qiling, address: int, params):
	return common.InstallConfigurationTable(ql.loader.smm_context, params)

@dxeapi(params = {
	"type"		: INT,			# EFI_ALLOCATE_TYPE
	"MemoryType": INT,			# EFI_MEMORY_TYPE
	"Pages"		: ULONGLONG,	# UINTN
	"Memory"	: POINTER		# PTR(EFI_PHYSICAL_ADDRESS)
})
def hook_SmmAllocatePages(ql: Qiling, address: int, params):
	alloc_size = params["Pages"] * PAGE_SIZE

	if params['type'] == EFI_ALLOCATE_TYPE.AllocateAddress:
		address = read_int64(ql, params["Memory"])

		# TODO: check the range [address, address + alloc_size] is available first
		ql.mem.map(address, alloc_size)
	else:
		# TODO: allocate memory according to 'MemoryType'
		address = ql.loader.smm_context.heap.alloc(alloc_size)

		if address == 0:
			return EFI_OUT_OF_RESOURCES

		write_int64(ql, params["Memory"], address)

	return EFI_SUCCESS

@dxeapi(params = {
	"Memory"	: ULONGLONG,	# EFI_PHYSICAL_ADDRESS
	"Pages"		: ULONGLONG		# UINTN
})
def hook_SmmFreePages(ql: Qiling, address: int, params):
	address = params["Memory"]

	ret = ql.loader.smm_context.heap.free(address)

	return EFI_SUCCESS if ret else EFI_INVALID_PARAMETER

@dxeapi(params = {
	"PoolType"	: INT,		# EFI_MEMORY_TYPE
	"Size"		: INT,		# UINTN
	"Buffer"	: POINTER	# PTR(PTR(VOID))
})
def hook_SmmAllocatePool(ql: Qiling, address: int, params):
	# TODO: allocate memory acording to "PoolType"
	address = ql.loader.smm_context.heap.alloc(params["Size"])
	write_int64(ql, params["Buffer"], address)

	return EFI_SUCCESS if address else EFI_OUT_OF_RESOURCES

@dxeapi(params = {
	"Buffer": POINTER # PTR(VOID)
})
def hook_SmmFreePool(ql: Qiling, address: int, params):
	address = params["Buffer"]
	ret = ql.loader.smm_context.heap.free(address)

	return EFI_SUCCESS if ret else EFI_INVALID_PARAMETER

@dxeapi(params = {
	"Procedure"		: POINTER,
	"CpuNumber"		: INT,
	"ProcArguments"	: POINTER
})
def hook_SmmStartupThisAp(ql: Qiling, address: int, params):
	return EFI_INVALID_PARAMETER

@dxeapi(params = {
	"Handle"		: POINTER,		# PTR(EFI_HANDLE)
	"Protocol"		: GUID,			# PTR(EFI_GUID)
	"InterfaceType"	: ULONGLONG,	# EFI_INTERFACE_TYPE
	"Interface"		: POINTER,		# PTR(VOID)
})
def hook_SmmInstallProtocolInterface(ql: Qiling, address: int, params):
	return common.InstallProtocolInterface(ql.loader.smm_context, params)

@dxeapi(params = {
	"Handle"	: POINTER,	# EFI_HANDLE
	"Protocol"	: GUID,		# PTR(EFI_GUID)
	"Interface"	: POINTER	# PTR(VOID)
})
def hook_SmmUninstallProtocolInterface(ql: Qiling, address: int, params):
	return common.UninstallProtocolInterface(ql.loader.smm_context, params)

@dxeapi(params = {
	"Handle"	: POINTER,	# EFI_HANDLE
	"Protocol"	: GUID,		# PTR(EFI_GUID)
	"Interface"	: POINTER	# PTR(PTR(VOID))
})
def hook_SmmHandleProtocol(ql: Qiling, address: int, params):
	return common.HandleProtocol(ql.loader.smm_context, params)

@dxeapi(params = {
	"Protocol"		: GUID,		# PTR(EFI_GUID)
	"Function"		: POINTER,	# EFI_MM_NOTIFY_FN
	"Registration"	: POINTER	# PTR(PTR(VOID))
})
def hook_SmmRegisterProtocolNotify(ql: Qiling, address: int, params):
	event_id = len(ql.loader.events)
	event_dic = {
		"NotifyFunction": params["Function"],
		"CallbackArgs"	: None,
		"Guid"			: params["Protocol"],
		"Set"			: False
	}
	ql.loader.events[event_id] = event_dic
	ptr_write64(ql, params["Registration"], event_id)
	return EFI_SUCCESS

@dxeapi(params = {
	"SearchType": INT,		# EFI_LOCATE_SEARCH_TYPE
	"Protocol"	: GUID,		# PTR(EFI_GUID)
	"SearchKey"	: POINTER,	# PTR(VOID)
	"BufferSize": POINTER,	# PTR(UINTN)
	"Buffer"	: POINTER	# PTR(EFI_HANDLE)
})
def hook_SmmLocateHandle(ql: Qiling, address: int, params):
	return common.LocateHandle(ql.loader.smm_context, params)

@dxeapi(params = {
	"Protocol"		: GUID,		# PTR(EFI_GUID)
	"Registration"	: POINTER,	# PTR(VOID)
	"Interface"		: POINTER	# PTR(PTR(VOID))
})
def hook_SmmLocateProtocol(ql: Qiling, address: int, params):
	return common.LocateProtocol(ql.loader.smm_context, params)

@dxeapi(params = {
	"HandlerType"	: GUID,
	"Context"		: POINTER,
	"CommBuffer"	: POINTER,
	"CommBufferSize": POINTER
})
def hook_SmiManage(ql: Qiling, address: int, params):
	return EFI_NOT_FOUND

@dxeapi(params = {
	"Handler"		: POINTER,
	"HandlerType"	: GUID,
	"DispatchHandle": POINTER
})
def hook_SmiHandlerRegister(ql: Qiling, address: int, params):
	return EFI_SUCCESS

@dxeapi(params = {
	"DispatchHandle": POINTER
})
def hook_SmiHandlerUnRegister(ql: Qiling, address: int, params):
	return EFI_SUCCESS

def initialize(ql: Qiling, context, gSmst: int):
	ql.loader.gSmst = gSmst

	gSmmRT = gSmst + EFI_SMM_SYSTEM_TABLE2.sizeof()	# smm runtime services
	cfg = gSmmRT + EFI_RUNTIME_SERVICES.sizeof()	# configuration tables array

	rt.initialize(ql, gSmmRT)

	descriptor = {
		'struct' : EFI_SMM_SYSTEM_TABLE2,
		'fields' : (
			('Hdr',								None),
			('SmmFirmwareVendor',				None),
			('SmmFirmwareRevision',				None),
			('SmmInstallConfigurationTable',	hook_SmmInstallConfigurationTable),
			('SmmIo',							None),
			('SmmAllocatePool',					hook_SmmAllocatePool),
			('SmmFreePool',						hook_SmmFreePool),
			('SmmAllocatePages',				hook_SmmAllocatePages),
			('SmmFreePages',					hook_SmmFreePages),
			('SmmStartupThisAp',				hook_SmmStartupThisAp),
			('CurrentlyExecutingCpu',			None),
			('NumberOfCpus',					None),
			('CpuSaveStateSize',				None),
			('CpuSaveState',					None),
			('NumberOfTableEntries',			0),
			('SmmConfigurationTable',			cfg),
			('SmmInstallProtocolInterface',		hook_SmmInstallProtocolInterface),
			('SmmUninstallProtocolInterface',	hook_SmmUninstallProtocolInterface),
			('SmmHandleProtocol',				hook_SmmHandleProtocol),
			('SmmRegisterProtocolNotify',		hook_SmmRegisterProtocolNotify),
			('SmmLocateHandle',					hook_SmmLocateHandle),
			('SmmLocateProtocol',				hook_SmmLocateProtocol),
			('SmiManage',						hook_SmiManage),
			('SmiHandlerRegister',				hook_SmiHandlerRegister),
			('SmiHandlerUnRegister',			hook_SmiHandlerUnRegister),
		)
	}

	instance = init_struct(ql, gSmst, descriptor)
	instance.saveTo(ql, gSmst)

	install_configuration_table(context, "HOB_LIST", None)
	install_configuration_table(context, "SMM_RUNTIME_SERVICES_TABLE", gSmmRT)

__all__ = [
	'EFI_SMM_SYSTEM_TABLE2',
	'initialize'
]
