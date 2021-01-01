#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from qiling.os.const import *
from qiling.os.uefi.const import *
from ..fncc import *
from ..ProcessorBind import *
from ..UefiBaseType import *
from ..utils import write_int64

# @see: MdePkg\Include\Pi\PiMultiPhase.h
class EFI_MMRAM_DESCRIPTOR(STRUCT):
	_fields_ = [
		('PhysicalStart',	EFI_PHYSICAL_ADDRESS),
		('CpuStart',		EFI_PHYSICAL_ADDRESS),
		('PhysicalSize',	UINT64),
		('RegionState',		UINT64)
	]

# @see: MdePkg\Include\Protocol\MmAccess.h
class EFI_SMM_ACCESS2_PROTOCOL(STRUCT):
	EFI_SMM_ACCESS2_PROTOCOL = STRUCT

	_fields_ = [
		('Open',			FUNCPTR(EFI_STATUS, PTR(EFI_SMM_ACCESS2_PROTOCOL))),
		('Close',			FUNCPTR(EFI_STATUS, PTR(EFI_SMM_ACCESS2_PROTOCOL))),
		('Lock',			FUNCPTR(EFI_STATUS, PTR(EFI_SMM_ACCESS2_PROTOCOL))),
		('GetCapabilities',	FUNCPTR(EFI_STATUS, PTR(EFI_SMM_ACCESS2_PROTOCOL), PTR(UINTN), PTR(EFI_MMRAM_DESCRIPTOR))),
		('LockState',		BOOLEAN),
		('OpenState',		BOOLEAN),
		('PADDING_0',		CHAR8 * 6)
	]

@dxeapi(params = {
	"This" : POINTER
})
def hook_Open(ql, address, params):
	return EFI_UNSUPPORTED

@dxeapi(params = {
	"This" : POINTER
})
def hook_Close(ql, address, params):
	return EFI_UNSUPPORTED

@dxeapi(params = {
	"This" : POINTER
})
def hook_Lock(ql, address, params):
	return EFI_UNSUPPORTED

@dxeapi(params = {
	"This"          : POINTER,
	"MmramMapSize"  : POINTER,
	"MmramMap"      : POINTER
})
def hook_GetCapabilities(ql, address, params):
	write_int64(ql, params["MmramMapSize"], 0)

	if params['MmramMap'] != 0:
		write_int64(ql, params["MmramMap"], 0)

	return EFI_SUCCESS

descriptor = {
	"guid" : "c2702b74-800c-4131-8746-8fb5b89ce4ac",
	"struct" : EFI_SMM_ACCESS2_PROTOCOL,
	"fields" : (
		("Open",			hook_Open),
		("Close",			hook_Close),
		("Lock",			hook_Lock),
		("GetCapabilities",	hook_GetCapabilities)
	)
}
