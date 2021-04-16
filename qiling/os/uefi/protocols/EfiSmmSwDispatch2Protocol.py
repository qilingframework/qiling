#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.const import *
from ..const import *
from ..fncc import *
from ..ProcessorBind import *
from ..UefiBaseType import *
from .. import utils

MAXIMUM_SWI_VALUE = 0xff

class EFI_SMM_SW_CONTEXT(STRUCT):
	_fields_ = [
		('SwSmiCpuIndex',	UINTN),	# index of the cpu which generated the swsmi
		('CommandPort',		UINT8),	# port number used to trigger the swsmi
		('DataPort',		UINT8)	# irrelevant
	]

# @file: MdePkg\Include\Protocol\SmmSwDispatch2.h
class EFI_SMM_SW_REGISTER_CONTEXT(STRUCT):
	_fields_ = [
		('SwSmiInputValue', UINTN)
	]

# @ file: MdePkg\Include\Pi\PiMmCis.h
EFI_SMM_HANDLER_ENTRY_POINT2 = FUNCPTR(EFI_STATUS, EFI_HANDLE, PTR(VOID), PTR(VOID), PTR(UINTN))

class EFI_SMM_SW_DISPATCH2_PROTOCOL(STRUCT):
	EFI_SMM_SW_DISPATCH2_PROTOCOL = STRUCT

	_fields_ = [
		('Register',		FUNCPTR(EFI_STATUS, PTR(EFI_SMM_SW_DISPATCH2_PROTOCOL), EFI_SMM_HANDLER_ENTRY_POINT2, PTR(EFI_SMM_SW_REGISTER_CONTEXT), PTR(EFI_HANDLE))),
		('UnRegister',		FUNCPTR(EFI_STATUS, PTR(EFI_SMM_SW_DISPATCH2_PROTOCOL), EFI_HANDLE)),
		('MaximumSwiValue',	UINTN)
	]

@dxeapi(params = {
	"This"				: POINTER,	# PTR(EFI_SMM_SW_DISPATCH2_PROTOCOL)
	"DispatchFunction"	: POINTER,	# EFI_SMM_HANDLER_ENTRY_POINT2
	"RegisterContext"	: POINTER,	# PTR(EFI_SMM_SW_REGISTER_CONTEXT)
	"DispatchHandle"	: POINTER	# PTR(EFI_HANDLE)
})
def hook_Register(ql: Qiling, address: int, params):
	DispatchFunction: int = params['DispatchFunction']
	RegisterContext: int = params['RegisterContext']
	DispatchHandle: int = params['DispatchHandle']

	if DispatchFunction == 0 or DispatchHandle == 0:
		return EFI_INVALID_PARAMETER

	handlers = ql.loader.smm_context.swsmi_handlers

	SwRegisterContext = EFI_SMM_SW_REGISTER_CONTEXT.loadFrom(ql, RegisterContext)
	idx = SwRegisterContext.SwSmiInputValue

	# a value of -1 indicates that the swsmi index for this handler is flexible and
	# should be assigned by the protocol
	if idx == 0xffffffff:
		idx = next((i for i in range(1, MAXIMUM_SWI_VALUE) if i not in handlers), None)

		if idx is None:
			return EFI_OUT_OF_RESOURCES

		SwRegisterContext.SwSmiInputValue = idx
		SwRegisterContext.saveTo(ql, RegisterContext)

	else:
		This = EFI_SMM_SW_DISPATCH2_PROTOCOL.loadFrom(ql, params['This'])

		if idx in handlers:
			return EFI_INVALID_PARAMETER

		if idx > This.MaximumSwiValue:
			return EFI_INVALID_PARAMETER

	# prepare the context for the sw smi handler
	SwContext = EFI_SMM_SW_CONTEXT()
	SwContext.SwSmiCpuIndex = 0
	SwContext.CommandPort = idx
	SwContext.DataPort = 0

	# allocate handle and return it through out parameter
	Handle = ql.loader.smm_context.heap.alloc(ql.pointersize)
	utils.write_int64(ql, DispatchHandle, Handle)

	args = {
		'DispatchHandle'	: Handle,
		'SwRegisterContext'	: SwRegisterContext,
		'SwContext'			: SwContext,
		'CommBufferSize'	: 0
	}

	handlers[idx] = (DispatchFunction, args)

	return EFI_SUCCESS

@dxeapi(params = {
	"This"				: POINTER,
	"DispatchHandle"	: POINTER
})
def hook_UnRegister(ql: Qiling, address: int, params):
	DispatchHandle: int = params['DispatchHandle']

	handlers = ql.loader.smm_context.swsmi_handlers
	heap = ql.loader.smm_context.heap

	idx = next((idx for idx, (_, args) in handlers.items() if args['DispatchHandle'] == DispatchHandle), None)

	if idx is None:
		return EFI_INVALID_PARAMETER

	heap.free(DispatchHandle)
	del handlers[idx]

	return EFI_SUCCESS

descriptor = {
	"guid" : "18a3c6dc-5eea-48c8-a1c1-b53389f98999",
	"struct" : EFI_SMM_SW_DISPATCH2_PROTOCOL,
	"fields" : (
		("Register",		hook_Register),
		("UnRegister",		hook_UnRegister),
		('MaximumSwiValue',	MAXIMUM_SWI_VALUE)
	)
}
