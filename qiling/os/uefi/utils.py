#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from uuid import UUID

from qiling.os.uefi.const import EFI_SUCCESS, EFI_INVALID_PARAMETER
from qiling.os.uefi.UefiSpec import EFI_CONFIGURATION_TABLE
from qiling.os.uefi.UefiBaseType import EFI_GUID

def check_and_notify_protocols(ql):
	if ql.loader.notify_list:
		event_id, notify_func, notify_context = ql.loader.notify_list.pop(0)
		ql.log.info(f'Notify event:{event_id} calling:{notify_func:x} context:{notify_context:x}')

		ql.loader.call_function(notify_func, [notify_context], ql.loader.end_of_execution_ptr)

		return True

	return False

def ptr_read8(ql, addr : int) -> int:
	"""Read BYTE data from a pointer
	"""

	return ql.unpack8(ql.mem.read(addr, 1))

def ptr_write8(ql, addr : int, val : int):
	"""Write BYTE data to a pointer
	"""

	ql.mem.write(addr, ql.pack8(val))

def ptr_read32(ql, addr : int) -> int:
	"""Read DWORD data from a pointer
	"""

	return ql.unpack32(ql.mem.read(addr, 4))

def ptr_write32(ql, addr : int, val : int):
	"""Write DWORD data to a pointer
	"""

	ql.mem.write(addr, ql.pack32(val))

def ptr_read64(ql, addr : int) -> int:
	"""Read QWORD data from a pointer
	"""

	return ql.unpack64(ql.mem.read(addr, 8))

def ptr_write64(ql, addr : int, val : int):
	"""Write QWORD data to a pointer
	"""

	ql.mem.write(addr, ql.pack64(val))

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

def str_to_guid(guid: str) -> EFI_GUID:
	"""Construct an EFI_GUID structure out of a plain GUID string.
	"""

	buff = UUID(hex=guid).bytes_le

	return EFI_GUID.from_buffer_copy(buff)

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

	instance = EFI_CONFIGURATION_TABLE()
	instance.VendorGuid = str_to_guid(guid)
	instance.VendorTable = table
	instance.saveTo(ql, ptr)

	return EFI_SUCCESS

def GetEfiConfigurationTable(ql, guid: str) -> Optional[int]:
	"""Find a configuration table by its GUID.
	"""

	guid = guid.lower()
	confs = ql.loader.efi_conf_table_array

	if guid in confs:
		idx = confs.index(guid)
		ptr = ql.loader.efi_conf_table_array_ptr + (idx * EFI_CONFIGURATION_TABLE.sizeof())

		return ptr

	# not found
	return None
