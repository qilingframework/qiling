#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.uefi.context import UefiContext
from qiling.os.uefi.utils import GetEfiConfigurationTable, CompareGuid, str_to_guid
from qiling.os.uefi.UefiBaseType import STRUCT, EFI_GUID, UINT32, UINT16
from qiling.os.uefi.UefiSpec import EFI_CONFIGURATION_TABLE

EFI_HOB_TYPE_HANDOFF		 = 0x0001
EFI_HOB_TYPE_GUID_EXTENSION	 = 0x0004
EFI_HOB_TYPE_END_OF_HOB_LIST = 0xffff

class EFI_HOB_GENERIC_HEADER(STRUCT):
	_fields_ = [
		('HobType',		UINT16),
		('HobLength',	UINT16),
		('Reserved',	UINT32)
	]

class EFI_HOB_GUID_TYPE(STRUCT):
	_fields_ = [
		('Header',	EFI_HOB_GENERIC_HEADER),
		('Name',	EFI_GUID)
	]

def GetHobList(ql: Qiling, context: UefiContext) -> int:
	"""Get HOB list location in memory (ostensibly set by PEI).
	"""

	conftable_guid = ql.os.profile['HOB_LIST']['Guid']
	conftable_ptr = GetEfiConfigurationTable(context, conftable_guid)
	conftable = EFI_CONFIGURATION_TABLE.loadFrom(ql, conftable_ptr)

	return ql.unpack64(conftable.VendorTable)

def CreateHob(ql: Qiling, context: UefiContext, hob) -> int:
	"""Add a HOB to the end of the HOB list.
	"""

	hoblist = GetHobList(ql, context)

	# look for the list end marker; uefi codebase assumes there is
	# always one
	hoblist = GetNextHob(ql, EFI_HOB_TYPE_END_OF_HOB_LIST, hoblist)

	# overwrite end marker with the hob
	pHob = hoblist
	hob.saveTo(ql, pHob)
	hoblist += hob.sizeof()

	# create a new end marker istead, following the hob
	marker = EFI_HOB_GENERIC_HEADER()
	marker.HobType = EFI_HOB_TYPE_END_OF_HOB_LIST
	marker.HobLength = 0x0000
	marker.Reserved = 0x00000000
	marker.saveTo(ql, hoblist)

	# return the address the hob was written to; it might be useful
	return pHob

def GetNextHob(ql: Qiling, hobtype: int, hoblist: int) -> int:
	"""Get next HOB on the list.
	"""

	hobaddr = hoblist

	while True:
		header = EFI_HOB_GENERIC_HEADER.loadFrom(ql, hobaddr)

		# found the hob?
		if header.HobType == hobtype:
			break

		# reached end of hob list?
		if header.HobType == EFI_HOB_TYPE_END_OF_HOB_LIST:
			return 0

		hobaddr += header.HobLength

	return hobaddr

def GetNextGuidHob(ql: Qiling, guid: str, hoblist: int):
	"""Find next HOB with the specified GUID.
	"""

	hobguid = str_to_guid(guid)
	hobaddr = hoblist

	while True:
		hobaddr = GetNextHob(ql, EFI_HOB_TYPE_GUID_EXTENSION, hobaddr)

		if not hobaddr:
			return 0

		hob = EFI_HOB_GUID_TYPE.loadFrom(ql, hobaddr)

		if CompareGuid(hob.Name, hobguid):
			break

		hobaddr += hob.Header.HobLength

	return hobaddr
