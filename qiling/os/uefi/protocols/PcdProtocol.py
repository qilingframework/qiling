#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.os.const import *
from ..fncc import *
from ..ProcessorBind import *
from ..UefiBaseType import *

PCD_PROTOCOL_CALLBACK = FUNCPTR(VOID, PTR(EFI_GUID), UINTN, PTR(VOID), UINTN)

PCD_PROTOCOL_SET_SKU		= FUNCPTR(VOID, UINTN)
PCD_PROTOCOL_GET8			= FUNCPTR(UINT8, UINTN)
PCD_PROTOCOL_GET16			= FUNCPTR(UINT16, UINTN)
PCD_PROTOCOL_GET32			= FUNCPTR(UINT32, UINTN)
PCD_PROTOCOL_GET64			= FUNCPTR(UINT64, UINTN)
PCD_PROTOCOL_GET_POINTER	= FUNCPTR(PTR(VOID), UINTN)
PCD_PROTOCOL_GET_BOOLEAN	= FUNCPTR(BOOLEAN, UINTN)
PCD_PROTOCOL_GET_SIZE		= FUNCPTR(UINTN, UINTN)
PCD_PROTOCOL_GET_EX_8		= FUNCPTR(UINT8, PTR(EFI_GUID), UINTN)
PCD_PROTOCOL_GET_EX_16		= FUNCPTR(UINT16, PTR(EFI_GUID), UINTN)
PCD_PROTOCOL_GET_EX_32		= FUNCPTR(UINT32, PTR(EFI_GUID), UINTN)
PCD_PROTOCOL_GET_EX_64		= FUNCPTR(UINT64, PTR(EFI_GUID), UINTN)
PCD_PROTOCOL_GET_EX_POINTER	= FUNCPTR(PTR(VOID), PTR(EFI_GUID), UINTN)
PCD_PROTOCOL_GET_EX_BOOLEAN	= FUNCPTR(BOOLEAN, PTR(EFI_GUID), UINTN)
PCD_PROTOCOL_GET_EX_SIZE	= FUNCPTR(UINTN, PTR(EFI_GUID), UINTN)
PCD_PROTOCOL_SET8			= FUNCPTR(EFI_STATUS, UINTN, UINT8)
PCD_PROTOCOL_SET16			= FUNCPTR(EFI_STATUS, UINTN, UINT16)
PCD_PROTOCOL_SET32			= FUNCPTR(EFI_STATUS, UINTN, UINT32)
PCD_PROTOCOL_SET64			= FUNCPTR(EFI_STATUS, UINTN, UINT64)
PCD_PROTOCOL_SET_POINTER	= FUNCPTR(EFI_STATUS, UINTN, PTR(UINTN), PTR(VOID))
PCD_PROTOCOL_SET_BOOLEAN	= FUNCPTR(EFI_STATUS, UINTN, BOOLEAN)
PCD_PROTOCOL_SET_EX_8		= FUNCPTR(EFI_STATUS, PTR(EFI_GUID), UINTN, UINT8)
PCD_PROTOCOL_SET_EX_16		= FUNCPTR(EFI_STATUS, PTR(EFI_GUID), UINTN, UINT16)
PCD_PROTOCOL_SET_EX_32		= FUNCPTR(EFI_STATUS, PTR(EFI_GUID), UINTN, UINT32)
PCD_PROTOCOL_SET_EX_64		= FUNCPTR(EFI_STATUS, PTR(EFI_GUID), UINTN, UINT64)
PCD_PROTOCOL_SET_EX_POINTER	= FUNCPTR(EFI_STATUS, PTR(EFI_GUID), UINTN, PTR(UINTN), PTR(VOID))
PCD_PROTOCOL_SET_EX_BOOLEAN	= FUNCPTR(EFI_STATUS, PTR(EFI_GUID), UINTN, BOOLEAN)
PCD_PROTOCOL_CALLBACK_ONSET	= FUNCPTR(EFI_STATUS, PTR(EFI_GUID), UINTN, PCD_PROTOCOL_CALLBACK)
PCD_PROTOCOL_CANCEL_CALLBACK= FUNCPTR(EFI_STATUS, PTR(EFI_GUID), UINTN, PCD_PROTOCOL_CALLBACK)
PCD_PROTOCOL_GET_NEXT_TOKEN	= FUNCPTR(EFI_STATUS, PTR(EFI_GUID), PTR(UINTN))
PCD_PROTOCOL_GET_NEXT_TOKENSPACE = FUNCPTR(EFI_STATUS, PTR(PTR(EFI_GUID)))

class PCD_PROTOCOL(STRUCT):
	_fields_ = [
		('SetSku',				PCD_PROTOCOL_SET_SKU),
		('Get8',				PCD_PROTOCOL_GET8),
		('Get16',				PCD_PROTOCOL_GET16),
		('Get32',				PCD_PROTOCOL_GET32),
		('Get64',				PCD_PROTOCOL_GET64),
		('GetPtr',				PCD_PROTOCOL_GET_POINTER),
		('GetBool',				PCD_PROTOCOL_GET_BOOLEAN),
		('GetSize',				PCD_PROTOCOL_GET_SIZE),
		('Get8Ex',				PCD_PROTOCOL_GET_EX_8),
		('Get16Ex',				PCD_PROTOCOL_GET_EX_16),
		('Get32Ex',				PCD_PROTOCOL_GET_EX_32),
		('Get64Ex',				PCD_PROTOCOL_GET_EX_64),
		('GetPtrEx',			PCD_PROTOCOL_GET_EX_POINTER),
		('GetBoolEx',			PCD_PROTOCOL_GET_EX_BOOLEAN),
		('GetSizeEx',			PCD_PROTOCOL_GET_EX_SIZE),
		('Set8',				PCD_PROTOCOL_SET8),
		('Set16',				PCD_PROTOCOL_SET16),
		('Set32',				PCD_PROTOCOL_SET32),
		('Set64',				PCD_PROTOCOL_SET64),
		('SetPtr',				PCD_PROTOCOL_SET_POINTER),
		('SetBool',				PCD_PROTOCOL_SET_BOOLEAN),
		('Set8Ex',				PCD_PROTOCOL_SET_EX_8),
		('Set16Ex',				PCD_PROTOCOL_SET_EX_16),
		('Set32Ex',				PCD_PROTOCOL_SET_EX_32),
		('Set64Ex',				PCD_PROTOCOL_SET_EX_64),
		('SetPtrEx',			PCD_PROTOCOL_SET_EX_POINTER),
		('SetBoolEx',			PCD_PROTOCOL_SET_EX_BOOLEAN),
		('CallbackOnSet',		PCD_PROTOCOL_CALLBACK_ONSET),
		('CancelCallback',		PCD_PROTOCOL_CANCEL_CALLBACK),
		('GetNextToken',		PCD_PROTOCOL_GET_NEXT_TOKEN),
		('GetNextTokenSpace',	PCD_PROTOCOL_GET_NEXT_TOKENSPACE)
	]

@dxeapi(params = {
	"SkuId" : UINT
})
def hook_SetSku(ql, address, params):
	pass

@dxeapi(params = {
	"TokenNumber" : UINT
})
def hook_Get8(ql, address, params):
	pass

@dxeapi(params = {
	"TokenNumber" : UINT
})
def hook_Get16(ql, address, params):
	pass

@dxeapi(params = {
	"TokenNumber" : UINT
})
def hook_Get32(ql, address, params):
	pass

@dxeapi(params = {
	"TokenNumber" : UINT
})
def hook_Get64(ql, address, params):
	pass

@dxeapi(params = {
	"TokenNumber" : UINT
})
def hook_GetPtr(ql, address, params):
	pass

@dxeapi(params = {
	"TokenNumber" : UINT
})
def hook_GetBool(ql, address, params):
	pass

@dxeapi(params = {
	"TokenNumber" : UINT
})
def hook_GetSize(ql, address, params):
	pass

@dxeapi(params = {
	"Guid"			: GUID,
	"TokenNumber"	: UINT
})
def hook_Get8Ex(ql, address, params):
	pass

@dxeapi(params = {
	"Guid"			: GUID,
	"TokenNumber"	: UINT
})
def hook_Get16Ex(ql, address, params):
	pass

@dxeapi(params = {
	"Guid"			: GUID,
	"TokenNumber"	: UINT
})
def hook_Get32Ex(ql, address, params):
	pass

@dxeapi(params = {
	"Guid"			: GUID,
	"TokenNumber"	: UINT
})
def hook_Get64Ex(ql, address, params):
	pass

@dxeapi(params = {
	"Guid"			: GUID,
	"TokenNumber"	: UINT
})
def hook_GetPtrEx(ql, address, params):
	pass

@dxeapi(params = {
	"Guid"			: GUID,
	"TokenNumber"	: UINT
})
def hook_GetBoolEx(ql, address, params):
	pass

@dxeapi(params = {
	"Guid"			: GUID,
	"TokenNumber"	: UINT
})
def hook_GetSizeEx(ql, address, params):
	pass

@dxeapi(params = {
	"TokenNumber"	: UINT,
	"Value"			: INT
})
def hook_Set8(ql, address, params):
	pass

@dxeapi(params = {
	"TokenNumber"	: UINT,
	"Value"			: INT
})
def hook_Set16(ql, address, params):
	pass

@dxeapi(params = {
	"TokenNumber"	: UINT,
	"Value"			: INT
})
def hook_Set32(ql, address, params):
	pass

@dxeapi(params = {
	"TokenNumber"	: UINT,
	"Value"			: INT
})
def hook_Set64(ql, address, params):
	pass

@dxeapi(params = {
	"TokenNumber"	: UINT,
	"SizeOfValue"	: POINTER,
	"Buffer"		: POINTER
})
def hook_SetPtr(ql, address, params):
	pass

@dxeapi(params = {
	"TokenNumber"	: UINT,
	"Value"			: INT
})
def hook_SetBool(ql, address, params):
	pass

@dxeapi(params = {
	"Guid"			: GUID,
	"TokenNumber"	: UINT,
	"Value"			: INT
})
def hook_Set8Ex(ql, address, params):
	pass

@dxeapi(params = {
	"Guid"			: GUID,
	"TokenNumber"	: UINT,
	"Value"			: INT
})
def hook_Set16Ex(ql, address, params):
	pass

@dxeapi(params = {
	"Guid"			: GUID,
	"TokenNumber"	: UINT,
	"Value"			: INT
})
def hook_Set32Ex(ql, address, params):
	pass

@dxeapi(params = {
	"Guid"			: GUID,
	"TokenNumber"	: UINT,
	"Value"			: INT
})
def hook_Set64Ex(ql, address, params):
	pass

@dxeapi(params = {
	"Guid"			: GUID,
	"TokenNumber"	: UINT,
	"SizeOfValue"	: POINTER,
	"Buffer"		: POINTER
})
def hook_SetPtrEx(ql, address, params):
	pass

@dxeapi(params = {
	"Guid"			: GUID,
	"TokenNumber"	: UINT,
	"Value"			: INT
})
def hook_SetBoolEx(ql, address, params):
	pass

@dxeapi(params = {
	"Guid"				: GUID,
	"TokenNumber"		: UINT,
	"CallBackFunction"	: POINTER
})
def hook_CallbackOnSet(ql, address, params):
	pass

@dxeapi(params = {
	"Guid"				: GUID,
	"TokenNumber"		: UINT,
	"CallBackFunction"	: POINTER
})
def hook_CancelCallback(ql, address, params):
	pass

@dxeapi(params = {
	"Guid"			: GUID,
	"TokenNumber"	: POINTER
})
def hook_GetNextToken(ql, address, params):
	pass

@dxeapi(params = {
	"Guid" : POINTER
})
def hook_GetNextTokenSpace(ql, address, params):
	pass

descriptor = {
	"guid" : "11b34006-d85b-4d0a-a290-d5a571310ef7",
	"struct" : PCD_PROTOCOL,
	"fields" : (
		('SetSku',				hook_SetSku),
		('Get8',				hook_Get8),
		('Get16',				hook_Get16),
		('Get32',				hook_Get32),
		('Get64',				hook_Get64),
		('GetPtr',				hook_GetPtr),
		('GetBool',				hook_GetBool),
		('GetSize',				hook_GetSize),
		('Get8Ex',				hook_Get8Ex),
		('Get16Ex',				hook_Get16Ex),
		('Get32Ex',				hook_Get32Ex),
		('Get64Ex',				hook_Get64Ex),
		('GetPtrEx',			hook_GetPtrEx),
		('GetBoolEx',			hook_GetBoolEx),
		('GetSizeEx',			hook_GetSizeEx),
		('Set8',				hook_Set8),
		('Set16',				hook_Set16),
		('Set32',				hook_Set32),
		('Set64',				hook_Set64),
		('SetPtr',				hook_SetPtr),
		('SetBool',				hook_SetBool),
		('Set8Ex',				hook_Set8Ex),
		('Set16Ex',				hook_Set16Ex),
		('Set32Ex',				hook_Set32Ex),
		('Set64Ex',				hook_Set64Ex),
		('SetPtrEx',			hook_SetPtrEx),
		('SetBoolEx',			hook_SetBoolEx),
		('CallbackOnSet',		hook_CallbackOnSet),
		('CancelCallback',		hook_CancelCallback),
		('GetNextToken',		hook_GetNextToken),
		('GetNextTokenSpace',	hook_GetNextTokenSpace)
	)
}
