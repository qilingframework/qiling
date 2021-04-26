#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.os.const import *
from qiling.os.uefi.const import *
from ..fncc import *
from ..ProcessorBind import *
from ..UefiBaseType import *
from ..PiMultiPhase import *
from .. import utils

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
def hook_Open(ql: Qiling, address: int, params):
	ql.loader.smm_context.tseg_open = True

	return EFI_SUCCESS

@dxeapi(params = {
	"This" : POINTER
})
def hook_Close(ql: Qiling, address: int, params):
	ql.loader.smm_context.tseg_open = False

	return EFI_SUCCESS

@dxeapi(params = {
	"This" : POINTER
})
def hook_Lock(ql: Qiling, address: int, params):
	ql.loader.smm_context.tseg_locked = True

	return EFI_SUCCESS

def _coalesce(seq):
	"""Coalesce adjacent ranges on list, as long as they share the
	same attributes.
	"""

	res = []
	curr = seq[0]

	for item in seq[1:]:
		start, end, attr = item

		if start == curr[1] and attr == curr[2]:
			curr[1] = end
		else:
			res.append(curr)
			curr = item

	res.append(curr)

	return res

@dxeapi(params = {
	"This"          : POINTER,	# PTR(EFI_SMM_ACCESS2_PROTOCOL)
	"MmramMapSize"  : POINTER,	# IN OUT PTR(UINTN)
	"MmramMap"      : POINTER	# OUT PTR(EFI_MMRAM_DESCRIPTOR)
})
def hook_GetCapabilities(ql: Qiling, address: int, params):
	heap = ql.loader.smm_context.heap

	# get a copy of smm heap chunks list sorted by starting address
	chunks = sorted(heap.chunks, key=lambda c: c.address)

	# turn chunks objects into 3-item entries: [start, end, inuse]
	chunks = [[ch.address, ch.address + ch.size, ch.inuse] for ch in chunks]

	# if first chunk does not start at heap start, add a dummy free chunk there
	if chunks[0][0] != heap.start_address:
		chunks.insert(0, [heap.start_address, chunks[0].address, False])

	# if last chunk does not end at heap end, add a dummy free chunk there
	if (chunks[-1][1]) != heap.end_address:
		chunks.append([chunks[-1][1], heap.end_address, False])

	# coalesce adjacent free / used chunks on the list
	chunks = _coalesce(chunks)

	size = len(chunks) * EFI_SMRAM_DESCRIPTOR.sizeof()
	MmramMapSize = params["MmramMapSize"]

	if utils.read_int64(ql, MmramMapSize) < size:
		# since the caller cannot predict how much memory would be required for storing
		# the memory map, this method is normally called twice. the first one passes a
		# zero size only to determine the expected size, then the caller allocates the
		# required amount of memory and call it again.
		#
		# our memory map is managed differently from the real one, and memory allocations
		# are likely to generate an additional "map block" (or two, if allocated somewhere
		# in the last free heap chunk). because the caller allocates a new memory chunk
		# between the two calls, that would cause the second call to always complain the
		# buffer is too small.
		#
		# to work around that, we have the first call return a larger number than it should
		# have, to compensate on the coming allocation.
		extra = 2 * EFI_SMRAM_DESCRIPTOR.sizeof()

		utils.write_int64(ql, MmramMapSize, size + extra)
		return EFI_BUFFER_TOO_SMALL

	MmramMap = params["MmramMap"]

	state = EFI_CACHEABLE
	state |= EFI_SMRAM_OPEN if ql.loader.smm_context.tseg_open else EFI_SMRAM_CLOSED
	state |= EFI_SMRAM_LOCKED if ql.loader.smm_context.tseg_locked else 0

	for i, ch in enumerate(chunks):
		desc = EFI_SMRAM_DESCRIPTOR()
		desc.PhysicalStart = ch[0]
		desc.CpuStart = ch[0]
		desc.PhysicalSize = ch[1] - ch[0]
		desc.RegionState = state | (EFI_ALLOCATED if ch[2] else 0)

		desc.saveTo(ql, MmramMap + (i * desc.sizeof()))

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
