#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import struct

from uuid import UUID

from qiling.os.uefi.const import *
from qiling.os.uefi.UefiSpec import EFI_LOCATE_SEARCH_TYPE, EFI_CONFIGURATION_TABLE
from qiling.os.uefi.UefiBaseType import EFI_GUID

def check_and_notify_protocols(ql):
	if len(ql.loader.notify_list) > 0:
		event_id, notify_func, notify_context = ql.loader.notify_list.pop(0)
		ql.log.info(f'Notify event:{event_id} calling:{notify_func:x} context:{notify_context:x}')

		ql.stack_push(ql.loader.end_of_execution_ptr)
		ql.reg.rcx = notify_context
		ql.reg.arch_pc = notify_func

		return True

	return False

def ptr_read8(ql, addr : int) -> int:
	"""Read BYTE data from a pointer
	"""

	val = ql.mem.read(addr, 1)

	return struct.unpack('<B', val)[0]

def ptr_write8(ql, addr : int, val : int):
	"""Write BYTE data to a pointer
	"""

	ql.mem.write(addr, struct.pack('<B', val))

def ptr_read32(ql, addr : int) -> int:
	"""Read DWORD data from a pointer
	"""

	val = ql.mem.read(addr, 4)

	return struct.unpack('<I', val)[0]

def ptr_write32(ql, addr : int, val : int):
	"""Write DWORD data to a pointer
	"""

	ql.mem.write(addr, struct.pack('<I', val))

def ptr_read64(ql, addr : int) -> int:
	"""Read QWORD data from a pointer
	"""

	val = ql.mem.read(addr, 8)

	return struct.unpack('<Q', val)[0]

def ptr_write64(ql, addr : int, val : int):
	"""Write QWORD data to a pointer
	"""

	ql.mem.write(addr, struct.pack('<Q', val))

# backward comptability
read_int8   = ptr_read8
write_int8  = ptr_write8
read_int32  = ptr_read32
write_int32 = ptr_write32
read_int64  = ptr_read64
write_int64 = ptr_write64

def init_struct(ql, base : int, descriptor : dict):
	struct_class = descriptor['struct']
	struct_fields = descriptor.get('fields', [])

	isntance = struct_class()
	ql.log.info(f'Initializing {struct_class.__name__}')

	for name, value in struct_fields:
		if value is not None:
			# a method: hook this field
			if callable(value):
				p = base + struct_class.offsetof(name)

				isntance.__setattr__(name, p)
				ql.hook_address(value, p)

				ql.log.info(f' | {name:36s} {p:#010x}')

			# a value: set it
			else:
				isntance.__setattr__(name, value)

	ql.log.info(f'')

	return isntance

def LocateHandles(context, params):
	handles = []
	pointer_size = 8

	if params["SearchType"] == EFI_LOCATE_SEARCH_TYPE.AllHandles:
		handles = context.protocols.keys()
	elif params["SearchType"] == EFI_LOCATE_SEARCH_TYPE.ByProtocol:
		for handle, guid_dic in context.protocols.items():
			if params["Protocol"] in guid_dic:
				handles.append(handle)

	return len(handles) * pointer_size, handles

def LocateProtocol(context, params):
	protocol = params['Protocol']

	for handle, guid_dic in context.protocols.items():
		if "Handle" in params and params["Handle"] != handle:
			continue

		if protocol in guid_dic:
			# write protocol address to out variable Interface
			write_int64(context.ql, params['Interface'], guid_dic[protocol])
			return EFI_SUCCESS

	# (@wtdcode): please use ql.log.warning instead.
	#ql.log.warning(f'protocol with guid {protocol} not found')

	return EFI_NOT_FOUND

# see: MdeModulePkg/Core/Dxe/Misc/InstallConfigurationTable.c
def CoreInstallConfigurationTable(ql, guid: str, table: int) -> int:
	if not guid:
		return EFI_INVALID_PARAMETER

	guid = guid.lower()
	confs = ql.loader.efi_conf_table_array

	# find configuration table entry by guid. if found, idx would be set to the entry index
	# in the array. if not, idx would be set to one past end of array
	if guid not in confs:
		confs.append(guid)
		#TODO: gST.NumberOfTableEntries = len(confs)

	idx = confs.index(guid)
	ptr = ql.loader.efi_conf_table_array_ptr + (idx * EFI_CONFIGURATION_TABLE.sizeof())

	guid_bytes = UUID(hex=guid).bytes_le

	instance = EFI_CONFIGURATION_TABLE()
	instance.VendorGuid = EFI_GUID.from_buffer_copy(guid_bytes)
	instance.VendorTable = table
	instance.saveTo(ql, ptr)

	return EFI_SUCCESS
