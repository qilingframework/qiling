#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.const import *
from qiling.os.const import *
from .fncc import *
from .utils import init_struct
from .const import *
from .ProcessorBind import *
from .UefiBaseType import *
from .UefiMultiPhase import *

class EFI_GCD_MEMORY_TYPE(ENUM):
	_members_ = [
		'EfiGcdMemoryTypeNonExistent',
		'EfiGcdMemoryTypeReserved',
		'EfiGcdMemoryTypeSystemMemory',
		'EfiGcdMemoryTypeMemoryMappedIo',
		'EfiGcdMemoryTypePersistent',
		'EfiGcdMemoryTypePersistentMemory',
		'EfiGcdMemoryTypeMoreReliable',
		'EfiGcdMemoryTypeMaximum'
	]

class EFI_GCD_MEMORY_SPACE_DESCRIPTOR(STRUCT):
	_fields_ = [
		('BaseAddress',		EFI_PHYSICAL_ADDRESS),
		('Length',			UINT64),
		('Capabilities',	UINT64),
		('Attributes',		UINT64),
		('GcdMemoryType',	EFI_GCD_MEMORY_TYPE),
		('PADDING_0',		UINT8 * 4),
		('ImageHandle',		EFI_HANDLE),
		('DeviceHandle',	EFI_HANDLE)
	]

class EFI_GCD_IO_TYPE(ENUM):
	_members_ = [
		'EfiGcdIoTypeNonExistent',
		'EfiGcdIoTypeReserved',
		'EfiGcdIoTypeIo',
		'EfiGcdIoTypeMaximum'
	]

class EFI_GCD_IO_SPACE_DESCRIPTOR(STRUCT):
	_fields_ = [
		('BaseAddress',		EFI_PHYSICAL_ADDRESS),
		('Length',			UINT64),
		('GcdIoType',		EFI_GCD_IO_TYPE),
		('PADDING_0',		UINT8 * 4),
		('ImageHandle',		EFI_HANDLE),
		('DeviceHandle',	EFI_HANDLE)
	]

class EFI_GCD_ALLOCATE_TYPE(ENUM):
	_members_ = [
		'EfiGcdAllocateAnySearchBottomUp',
		'EfiGcdAllocateMaxAddressSearchBottomUp',
		'EfiGcdAllocateAddress',
		'EfiGcdAllocateAnySearchTopDown',
		'EfiGcdAllocateMaxAddressSearchTopDown',
		'EfiGcdMaxAllocateType'
	]

EFI_ADD_MEMORY_SPACE				= FUNCPTR(EFI_STATUS, EFI_GCD_MEMORY_TYPE, EFI_PHYSICAL_ADDRESS, UINT64, UINT64)
EFI_ALLOCATE_MEMORY_SPACE			= FUNCPTR(EFI_STATUS, EFI_GCD_ALLOCATE_TYPE, EFI_GCD_MEMORY_TYPE, UINTN, UINT64, PTR(EFI_PHYSICAL_ADDRESS), EFI_HANDLE, EFI_HANDLE)
EFI_FREE_MEMORY_SPACE				= FUNCPTR(EFI_STATUS, EFI_PHYSICAL_ADDRESS, UINT64)
EFI_REMOVE_MEMORY_SPACE 			= FUNCPTR(EFI_STATUS, EFI_PHYSICAL_ADDRESS, UINT64)
EFI_GET_MEMORY_SPACE_DESCRIPTOR		= FUNCPTR(EFI_STATUS, EFI_PHYSICAL_ADDRESS, PTR(EFI_GCD_MEMORY_SPACE_DESCRIPTOR))
EFI_SET_MEMORY_SPACE_ATTRIBUTES		= FUNCPTR(EFI_STATUS, EFI_PHYSICAL_ADDRESS, UINT64, UINT64)
EFI_GET_MEMORY_SPACE_MAP			= FUNCPTR(EFI_STATUS, PTR(UINTN), PTR(PTR(EFI_GCD_MEMORY_SPACE_DESCRIPTOR)))
EFI_ADD_IO_SPACE					= FUNCPTR(EFI_STATUS, EFI_GCD_IO_TYPE, EFI_PHYSICAL_ADDRESS, UINT64)
EFI_ALLOCATE_IO_SPACE				= FUNCPTR(EFI_STATUS, EFI_GCD_ALLOCATE_TYPE, EFI_GCD_IO_TYPE, UINTN, UINT64, PTR(EFI_PHYSICAL_ADDRESS), EFI_HANDLE, EFI_HANDLE)
EFI_FREE_IO_SPACE					= FUNCPTR(EFI_STATUS, EFI_PHYSICAL_ADDRESS, UINT64)
EFI_REMOVE_IO_SPACE					= FUNCPTR(EFI_STATUS, EFI_PHYSICAL_ADDRESS, UINT64)
EFI_GET_IO_SPACE_DESCRIPTOR			= FUNCPTR(EFI_STATUS, EFI_PHYSICAL_ADDRESS, PTR(EFI_GCD_IO_SPACE_DESCRIPTOR))
EFI_GET_IO_SPACE_MAP				= FUNCPTR(EFI_STATUS, PTR(UINTN), PTR(PTR(EFI_GCD_IO_SPACE_DESCRIPTOR)))
EFI_DISPATCH						= FUNCPTR(EFI_STATUS)
EFI_SCHEDULE						= FUNCPTR(EFI_STATUS, EFI_HANDLE, PTR(EFI_GUID))
EFI_TRUST							= FUNCPTR(EFI_STATUS, EFI_HANDLE, PTR(EFI_GUID))
EFI_PROCESS_FIRMWARE_VOLUME			= FUNCPTR(EFI_STATUS, PTR(VOID), UINTN, PTR(EFI_HANDLE))
EFI_SET_MEMORY_SPACE_CAPABILITIES	= FUNCPTR(EFI_STATUS, EFI_PHYSICAL_ADDRESS, UINT64, UINT64)

class EFI_DXE_SERVICES(STRUCT):
	_fields_ = [
		('Hdr',							EFI_TABLE_HEADER),
		('AddMemorySpace',				EFI_ADD_MEMORY_SPACE),
		('AllocateMemorySpace',			EFI_ALLOCATE_MEMORY_SPACE),
		('FreeMemorySpace',				EFI_FREE_MEMORY_SPACE),
		('RemoveMemorySpace',			EFI_REMOVE_MEMORY_SPACE),
		('GetMemorySpaceDescriptor',	EFI_GET_MEMORY_SPACE_DESCRIPTOR),
		('SetMemorySpaceAttributes',	EFI_SET_MEMORY_SPACE_ATTRIBUTES),
		('GetMemorySpaceMap',			EFI_GET_MEMORY_SPACE_MAP),
		('AddIoSpace',					EFI_ADD_IO_SPACE),
		('AllocateIoSpace',				EFI_ALLOCATE_IO_SPACE),
		('FreeIoSpace',					EFI_FREE_IO_SPACE),
		('RemoveIoSpace',				EFI_REMOVE_IO_SPACE),
		('GetIoSpaceDescriptor',		EFI_GET_IO_SPACE_DESCRIPTOR),
		('GetIoSpaceMap',				EFI_GET_IO_SPACE_MAP),
		('Dispatch',					EFI_DISPATCH),
		('Schedule',					EFI_SCHEDULE),
		('Trust',						EFI_TRUST),
		('ProcessFirmwareVolume',		EFI_PROCESS_FIRMWARE_VOLUME),
		('SetMemorySpaceCapabilities',	EFI_SET_MEMORY_SPACE_CAPABILITIES)
	]

@dxeapi(params={
	"a0": ULONGLONG,
	"a1": ULONGLONG,
	"a2": ULONGLONG,
	"a3": ULONGLONG,
})
def hook_AddMemorySpace(ctx, address, params):
	return EFI_OUT_OF_RESOURCES

@dxeapi(params={
	"a0": ULONGLONG,
	"a1": ULONGLONG,
	"a2": ULONGLONG,
	"a3": ULONGLONG,
	"a4": POINTER, #POINTER_T(ctypes.c_uint64)
	"a5": POINTER, #POINTER_T(None)
	"a6": POINTER, #POINTER_T(None)
})
def hook_AllocateMemorySpace(ctx, address, params):
	return EFI_OUT_OF_RESOURCES

@dxeapi(params={
	"a0": ULONGLONG,
	"a1": ULONGLONG,
})
def hook_FreeMemorySpace(ctx, address, params):
	return EFI_SUCCESS

@dxeapi(params={
	"a0": ULONGLONG,
	"a1": ULONGLONG,
})
def hook_RemoveMemorySpace(ctx, address, params):
	return EFI_SUCCESS

@dxeapi(params={
	"a0": ULONGLONG,
	"a1": POINTER, #POINTER_T(struct_EFI_GCD_MEMORY_SPACE_DESCRIPTOR)
})
def hook_GetMemorySpaceDescriptor(ctx, address, params):
	return EFI_UNSUPPORTED

@dxeapi(params={
	"a0": ULONGLONG,
	"a1": ULONGLONG,
	"a2": ULONGLONG,
})
def hook_SetMemorySpaceAttributes(ctx, address, params):
	return EFI_UNSUPPORTED

@dxeapi(params={
	"a0": POINTER, #POINTER_T(ctypes.c_uint64)
	"a1": POINTER, #POINTER_T(POINTER_T(struct_EFI_GCD_MEMORY_SPACE_DESCRIPTOR))
})
def hook_GetMemorySpaceMap(ctx, address, params):
	return EFI_UNSUPPORTED

@dxeapi(params={
	"a0": ULONGLONG,
	"a1": ULONGLONG,
	"a2": ULONGLONG,
})
def hook_AddIoSpace(ctx, address, params):
	return EFI_OUT_OF_RESOURCES

@dxeapi(params={
	"a0": ULONGLONG,
	"a1": ULONGLONG,
	"a2": ULONGLONG,
	"a3": ULONGLONG,
	"a4": POINTER, #POINTER_T(ctypes.c_uint64)
	"a5": POINTER, #POINTER_T(None)
	"a6": POINTER, #POINTER_T(None)
})
def hook_AllocateIoSpace(ctx, address, params):
	return EFI_OUT_OF_RESOURCES

@dxeapi(params={
	"a0": ULONGLONG,
	"a1": ULONGLONG,
})
def hook_FreeIoSpace(ctx, address, params):
	return EFI_SUCCESS

@dxeapi(params={
	"a0": ULONGLONG,
	"a1": ULONGLONG,
})
def hook_RemoveIoSpace(ctx, address, params):
	return EFI_SUCCESS

@dxeapi(params={
	"a0": ULONGLONG,
	"a1": POINTER, #POINTER_T(struct_EFI_GCD_IO_SPACE_DESCRIPTOR)
})
def hook_GetIoSpaceDescriptor(ctx, address, params):
	return EFI_NOT_FOUND

@dxeapi(params={
	"a0": POINTER, #POINTER_T(ctypes.c_uint64)
	"a1": POINTER, #POINTER_T(POINTER_T(struct_EFI_GCD_IO_SPACE_DESCRIPTOR))
})
def hook_GetIoSpaceMap(ctx, address, params):
	return EFI_OUT_OF_RESOURCES

@dxeapi(params={
})
def hook_Dispatch(ctx, address, params):
	return EFI_SUCCESS

@dxeapi(params={
	"a0": POINTER, #POINTER_T(None)
	"a1": GUID,
})
def hook_Schedule(ctx, address, params):
	return EFI_SUCCESS

@dxeapi(params={
	"a0": POINTER, #POINTER_T(None)
	"a1": GUID,
})
def hook_Trust(ctx, address, params):
	return EFI_NOT_FOUND

@dxeapi(params={
	"a0": POINTER, #POINTER_T(None)
	"a1": ULONGLONG,
	"a2": POINTER, #POINTER_T(POINTER_T(None))
})
def hook_ProcessFirmwareVolume(ctx, address, params):
	return EFI_OUT_OF_RESOURCES

@dxeapi(params={
	"a0": ULONGLONG,
	"a1": ULONGLONG,
	"a2": ULONGLONG,
})
def hook_SetMemorySpaceCapabilities(ctx, address, params):
	return EFI_UNSUPPORTED

def initialize(ql, gDS):
	descriptor = {
		'struct' : EFI_DXE_SERVICES,
		'fields' : (
			('Hdr',							None),
			('AddMemorySpace',				hook_AddMemorySpace),
			('AllocateMemorySpace',			hook_AllocateMemorySpace),
			('FreeMemorySpace',				hook_FreeMemorySpace),
			('RemoveMemorySpace',			hook_RemoveMemorySpace),
			('GetMemorySpaceDescriptor',	hook_GetMemorySpaceDescriptor),
			('SetMemorySpaceAttributes',	hook_SetMemorySpaceAttributes),
			('GetMemorySpaceMap',			hook_GetMemorySpaceMap),
			('AddIoSpace',					hook_AddIoSpace),
			('AllocateIoSpace',				hook_AllocateIoSpace),
			('FreeIoSpace',					hook_FreeIoSpace),
			('RemoveIoSpace',				hook_RemoveIoSpace),
			('GetIoSpaceDescriptor',		hook_GetIoSpaceDescriptor),
			('GetIoSpaceMap',				hook_GetIoSpaceMap),
			('Dispatch',					hook_Dispatch),
			('Schedule',					hook_Schedule),
			('Trust',						hook_Trust),
			('ProcessFirmwareVolume',		hook_ProcessFirmwareVolume),
			('SetMemorySpaceCapabilities',	hook_SetMemorySpaceCapabilities)
		)
	}

	instance = init_struct(ql, gDS, descriptor)
	instance.saveTo(ql, gDS)

__all__ = [
	'EFI_DXE_SERVICES',
	'initialize'
]
