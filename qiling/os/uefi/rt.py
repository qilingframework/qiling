#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.os.const import *
from .const import *
from .utils import *
from .fncc import *
from .ProcessorBind import *
from .UefiSpec import *

@dxeapi(params={
	"Time"			: POINTER,	# OUT PTR(EFI_TIME)
	"Capabilities"	: POINTER	# OUT PTR(EFI_TIME_CAPABILITIES)
})
def hook_GetTime(ql, address, params):
	return EFI_SUCCESS

@dxeapi(params={
	"Time": POINTER	# IN PTR(EFI_TIME)
})
def hook_SetTime(ql, address, params):
	return EFI_SUCCESS

@dxeapi(params={
	"Enabled"	: POINTER,	# OUT PTR(BOOLEAN)
	"Pending"	: POINTER,	# OUT PTR(BOOLEAN)
	"Time"		: POINTER	# OUT PTR(EFI_TIME)
})
def hook_GetWakeupTime(ql, address, params):
	return EFI_SUCCESS

@dxeapi(params={
	"Enable": BOOL,		# BOOLEAN
	"Time"	: POINTER	# PTR(EFI_TIME)
})
def hook_SetWakeupTime(ql, address, params):
	return EFI_SUCCESS

@dxeapi(params={
	"MemoryMapSize"		: UINT,		# UINTN
	"DescriptorSize"	: UINT,		# UINTN
	"DescriptorVersion"	: UINT,		# UINT32
	"VirtualMap"		: POINTER	# PTR(EFI_MEMORY_DESCRIPTOR)
})
def hook_SetVirtualAddressMap(ql, address, params):
	return EFI_SUCCESS

@dxeapi(params={
	"DebugDisposition"	: UINT,		# UINTN
	"Address"			: POINTER	# OUT PTR(PTR(VOID))
})
def hook_ConvertPointer(ql, address, params):
	return EFI_SUCCESS

@dxeapi(params={
	"VariableName"	: WSTRING,	# PTR(CHAR16)
	"VendorGuid"	: GUID,		# PTR(EFI_GUID)
	"Attributes"	: POINTER,	# OUT PTR(UINT32)
	"DataSize"		: POINTER,	# IN OUT PTR(UINTN)
	"Data"			: POINTER	# OUT PTR(VOID)
})
def hook_GetVariable(ql, address, params):
	name = params['VariableName']
	if name in ql.env:
		var = ql.env[name]
		read_len = read_int64(ql, params['DataSize'])
		if params['Attributes'] != 0:
			write_int64(ql, params['Attributes'], 0)
		write_int64(ql, params['DataSize'], len(var))
		if read_len < len(var):
			return EFI_BUFFER_TOO_SMALL
		if params['Data'] != 0:
			ql.mem.write(params['Data'], var)
		return EFI_SUCCESS
	ql.log.warning(f'variable with name {name} not found')
	return EFI_NOT_FOUND

@dxeapi(params={
	"VariableNameSize"	: POINTER,	# IN OUT PTR(UINTN)
	"VariableName"		: POINTER,	# IN OUT PTR(CHAR16)
	"VendorGuid"		: GUID		# IN OUT PTR(EFI_GUID)
})
def hook_GetNextVariableName(ql, address, params):
	name_size = read_int64(ql, params["VariableNameSize"])
	last_name = ql.os.utils.read_wstring(params["VariableName"])
	vars = ql.env['Names'] # This is a list of variable names in correct order.
	if last_name in vars and vars.index(last_name) < len(vars) - 1:
		new_name = vars[vars.index(last_name)+1]
		if (len(new_name)+1)*2 > name_size:
			return EFI_BUFFER_TOO_SMALL
		vn_ptr = params["VariableName"]
		for char in new_name:
			ql.mem.write(vn_ptr, char)
			vn_ptr += 1
			ql.mem.write(vn_ptr, '\x00')
			vn_ptr += 1
		ql.mem.write(vn_ptr, '\x00\x00')

	return EFI_INVALID_PARAMETER

@dxeapi(params={
	"VariableName"	: WSTRING,	# PTR(CHAR16)
	"VendorGuid"	: GUID,		# PTR(EFI_GUID)
	"Attributes"	: UINT,		# UINT32
	"DataSize"		: UINT,		# UINTN
	"Data"			: POINTER	# PTR(VOID)
})
def hook_SetVariable(ql, address, params):
	ql.env[params['VariableName']] = bytes(ql.mem.read(params['Data'], params['DataSize']))
	return EFI_SUCCESS

@dxeapi(params={
	"HighCount": POINTER	# OUT PTR(UINT32)
})
def hook_GetNextHighMonotonicCount(ql, address, params):
	ql.os.monotonic_count += 0x0000000100000000
	hmc = ql.os.monotonic_count
	hmc = (hmc >> 32) & 0xffffffff
	write_int32(ql, params["HighCount"], hmc)
	return EFI_SUCCESS

@dxeapi(params={
	"ResetType"		: INT,		# EFI_RESET_TYPE
	"ResetStatus"	: INT,		# EFI_STATUS
	"DataSize"		: UINT,		# UINTN
	"ResetData"		: POINTER	# PTR(VOID)
})
def hook_ResetSystem(ql, address, params):
	ql.emu_stop()

	return EFI_SUCCESS

@dxeapi(params={
	"CapsuleHeaderArray": POINTER,	# PTR(PTR(EFI_CAPSULE_HEADER))
	"CapsuleCount"		: UINT,		# UINTN
	"ScatterGatherList"	: ULONGLONG	# EFI_PHYSICAL_ADDRESS
})
def hook_UpdateCapsule(ql, address, params):
	return EFI_SUCCESS

@dxeapi(params={
	"CapsuleHeaderArray": POINTER,	# PTR(PTR(EFI_CAPSULE_HEADER))
	"CapsuleCount"		: UINT,		# UINTN
	"MaximumCapsuleSize": POINTER,	# OUT PTR(UINT64)
	"ResetType"			: POINTER	# OUT PTR(EFI_RESET_TYPE)
})
def hook_QueryCapsuleCapabilities(ql, address, params):
	return EFI_SUCCESS

@dxeapi(params={
	"Attributes"					: UINT,		# UINT32
	"MaximumVariableStorageSize"	: POINTER,	# OUT PTR(UINT64)
	"RemainingVariableStorageSize"	: POINTER,	# OUT PTR(UINT64)
	"MaximumVariableSize"			: POINTER	# OUT PTR(UINT64)
})
def hook_QueryVariableInfo(ql, address, params):
	return EFI_SUCCESS

def initialize(ql, gRT : int):
	descriptor = {
		'struct' : EFI_RUNTIME_SERVICES,
		'fields' : (
			('Hdr',							None),
			('GetTime',						hook_GetTime),
			('SetTime',						hook_SetTime),
			('GetWakeupTime',				hook_GetWakeupTime),
			('SetWakeupTime',				hook_SetWakeupTime),
			('SetVirtualAddressMap',		hook_SetVirtualAddressMap),
			('ConvertPointer',				hook_ConvertPointer),
			('GetVariable',					hook_GetVariable),
			('GetNextVariableName',			hook_GetNextVariableName),
			('SetVariable',					hook_SetVariable),
			('GetNextHighMonotonicCount',	hook_GetNextHighMonotonicCount),
			('ResetSystem',					hook_ResetSystem),
			('UpdateCapsule',				hook_UpdateCapsule),
			('QueryCapsuleCapabilities',	hook_QueryCapsuleCapabilities),
			('QueryVariableInfo',			hook_QueryVariableInfo)
		)
	}

	instance = init_struct(ql, gRT, descriptor)
	instance.saveTo(ql, gRT)

__all__ = [
	'initialize'
]