#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from .UefiBaseType import *
from .ProcessorBind import *

EFI_SMRAM_OPEN					= 0x00000001
EFI_SMRAM_CLOSED				= 0x00000002
EFI_SMRAM_LOCKED				= 0x00000004
EFI_CACHEABLE					= 0x00000008
EFI_ALLOCATED					= 0x00000010
EFI_NEEDS_TESTING				= 0x00000020
EFI_NEEDS_ECC_INITIALIZATION	= 0x00000040

class EFI_SMRAM_DESCRIPTOR(STRUCT):
	_fields_ = [
		('PhysicalStart',	EFI_PHYSICAL_ADDRESS),
		('CpuStart',		EFI_PHYSICAL_ADDRESS),
		('PhysicalSize',	UINT64),
		('RegionState',		UINT64)
	]

__all__ = [
	'EFI_SMRAM_DESCRIPTOR',
	'EFI_SMRAM_OPEN',
	'EFI_SMRAM_CLOSED',
	'EFI_SMRAM_LOCKED',
	'EFI_CACHEABLE',
	'EFI_ALLOCATED',
	'EFI_NEEDS_TESTING',
	'EFI_NEEDS_ECC_INITIALIZATION'
]
