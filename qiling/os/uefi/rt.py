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
	"a0": POINTER, #POINTER_T(struct_EFI_TIME)
	"a1": POINTER, #POINTER_T(struct_EFI_TIME_CAPABILITIES)
})
def hook_GetTime(ql, address, params):
	return EFI_SUCCESS

@dxeapi(params={
	"a0": POINTER, #POINTER_T(struct_EFI_TIME)
})
def hook_SetTime(ql, address, params):
	return EFI_SUCCESS

@dxeapi(params={
	"a0": POINTER, #POINTER_T(ctypes.c_ubyte)
	"a1": POINTER, #POINTER_T(ctypes.c_ubyte)
	"a2": POINTER, #POINTER_T(struct_EFI_TIME)
})
def hook_GetWakeupTime(ql, address, params):
	return EFI_SUCCESS

@dxeapi(params={
	"a0": ULONGLONG,
	"a1": POINTER, #POINTER_T(struct_EFI_TIME)
})
def hook_SetWakeupTime(ql, address, params):
	return EFI_SUCCESS

@dxeapi(params={
	"a0": ULONGLONG,
	"a1": ULONGLONG,
	"a2": UINT,
	"a3": POINTER, #POINTER_T(struct_EFI_MEMORY_DESCRIPTOR)
})
def hook_SetVirtualAddressMap(ql, address, params):
	return EFI_SUCCESS

@dxeapi(params={
	"a0": ULONGLONG,
	"a1": POINTER, #POINTER_T(POINTER_T(None))
})
def hook_ConvertPointer(ql, address, params):
	return EFI_SUCCESS

@dxeapi(params={
	"VariableName": WSTRING,
	"VendorGuid": GUID,
	"Attributes": POINTER,
	"DataSize": POINTER,
	"Data": POINTER
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
	"VariableNameSize": POINTER, #POINTER_T(ctypes.c_uint64)
	"VariableName": POINTER, #POINTER_T(ctypes.c_uint16)
	"VendorGuid": GUID,
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
	"VariableName": WSTRING, #POINTER_T(ctypes.c_uint16)
	"VendorGuid": GUID,
	"Attributes": UINT,
	"DataSize": ULONGLONG,
	"Data": POINTER, #POINTER_T(None)
})
def hook_SetVariable(ql, address, params):
	ql.env[params['VariableName']] = bytes(ql.mem.read(params['Data'], params['DataSize']))
	return EFI_SUCCESS

@dxeapi(params={
	"Count": POINTER, #POINTER_T(ctypes.c_uint32)
})
def hook_GetNextHighMonotonicCount(ql, address, params):
	ql.os.monotonic_count += 0x0000000100000000
	hmc = ql.os.monotonic_count
	hmc = (hmc >> 32) & 0xffffffff
	write_int32(ql, params["Count"], hmc)
	return EFI_SUCCESS

@dxeapi(params={
	"a0": ULONGLONG,
	"a1": ULONGLONG,
	"a2": ULONGLONG,
	"a3": POINTER, #POINTER_T(None)
})
def hook_ResetSystem(ql, address, params):
	ql.emu_stop()

	return EFI_SUCCESS

@dxeapi(params={
	"a0": POINTER, #POINTER_T(POINTER_T(struct_EFI_CAPSULE_HEADER))
	"a1": ULONGLONG,
	"a2": ULONGLONG,
})
def hook_UpdateCapsule(ql, address, params):
	return EFI_SUCCESS

@dxeapi(params={
	"a0": POINTER, #POINTER_T(POINTER_T(struct_EFI_CAPSULE_HEADER))
	"a1": ULONGLONG,
	"a2": POINTER, #POINTER_T(ctypes.c_uint64)
	"a3": POINTER, #POINTER_T(enum_73)
})
def hook_QueryCapsuleCapabilities(ql, address, params):
	return EFI_SUCCESS

@dxeapi(params={
	"a0": UINT,
	"a1": POINTER, #POINTER_T(ctypes.c_uint64)
	"a2": POINTER, #POINTER_T(ctypes.c_uint64)
	"a3": POINTER, #POINTER_T(ctypes.c_uint64)
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