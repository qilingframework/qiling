#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.os.const import *
from ..const import *
from ..fncc import *
from ..ProcessorBind import *
from ..UefiBaseType import *

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
	"This"				: POINTER,
	"DispatchFunction"	: POINTER,
	"RegisterContext"	: POINTER,
	"DispatchHandle"	: POINTER
})
def hook_Register(ql, address, params):
	# Let's save the dispatch params, so they can be triggered if needed. 
	ql.loader.smm_context.swsmi_handlers.append(params)
	return EFI_SUCCESS

@dxeapi(params = {
	"This"				: POINTER,
	"DispatchHandle"	: POINTER
})
def hook_UnRegister(ql, address, params):
	return EFI_SUCCESS

descriptor = {
	"guid" : "18a3c6dc-5eea-48c8-a1c1-b53389f98999",
	"struct" : EFI_SMM_SW_DISPATCH2_PROTOCOL,
	"fields" : (
		("Register",	hook_Register),
		("UnRegister",	hook_UnRegister)
	)
}
