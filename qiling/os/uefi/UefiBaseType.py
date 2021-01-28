#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.os.uefi.ProcessorBind import *

class EFI_GUID(STRUCT):
	_fields_ = [
		('Data1', UINT32),
		('Data2', UINT16),
		('Data3', UINT16),
		('Data4', UINT8 * 8)
	]

EFI_STATUS = UINTN
EFI_HANDLE = PTR(VOID)
EFI_EVENT = PTR(VOID)
EFI_TPL = UINTN
EFI_LBA = UINT64
EFI_PHYSICAL_ADDRESS = UINT64
EFI_VIRTUAL_ADDRESS = UINT64

class EFI_TIME(STRUCT):
	_fields_ = [
		('Year',		UINT16),
		('Month',		UINT8),
		('Day',			UINT8),
		('Hour',		UINT8),
		('Minute',		UINT8),
		('Second',		UINT8),
		('Pad1',		UINT8),
		('Nanosecond',	UINT32),
		('TimeZone',	UINT16),
		('Daylight',	UINT8),
		('Pad2',		UINT8)
	]

__all__ = [
	'EFI_GUID',
	'EFI_STATUS',
	'EFI_HANDLE',
	'EFI_EVENT',
	'EFI_TPL',
	'EFI_LBA',
	'EFI_PHYSICAL_ADDRESS',
	'EFI_VIRTUAL_ADDRESS',
	'EFI_TIME'
]
