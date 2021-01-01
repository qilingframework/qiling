#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import ctypes
import struct
import logging

from .const import *
from .UefiSpec import EFI_LOCATE_SEARCH_TYPE, EFI_CONFIGURATION_TABLE

def check_and_notify_protocols(ql):
	if len(ql.loader.notify_list) > 0:
		event_id, notify_func, notify_context = ql.loader.notify_list.pop(0)
		logging.info(f'Notify event:{event_id} calling:{notify_func:x} context:{notify_context:x}')

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
	logging.info(f'Initializing {struct_class.__name__}')

	for name, value in struct_fields:
		if value is not None:
			# a method: hook this field
			if callable(value):
				p = base + struct_class.offsetof(name)

				isntance.__setattr__(name, p)
				ql.hook_address(value, p)

				logging.info(f' | {name:36s} {p:#010x}')

			# a value: set it
			else:
				isntance.__setattr__(name, value)

	logging.info(f'')

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

	logging.warning(f'protocol with guid {protocol} not found')

	return EFI_NOT_FOUND

def to_byte_values(val, nbytes):
	while nbytes > 0:
		yield val & 0xff
		val >>= 8
		nbytes -= 1

# see: MdeModulePkg/Core/Dxe/Misc/InstallConfigurationTable.c
def CoreInstallConfigurationTable(ql, guid, table):
	if not guid:
		return EFI_INVALID_PARAMETER

	confs = ql.loader.efi_configuration_table

	# find configuration table entry by guid. if found, idx would be set to the entry index
	# in the array. if not, idx would be set to one past end of array
	if guid not in confs:
		confs.append(guid)
		#TODO: NumberOfTableEntries++

	idx = confs.index(guid)
	ptr = ql.loader.efi_configuration_table_ptr + (idx * EFI_CONFIGURATION_TABLE.sizeof())

	instance = EFI_CONFIGURATION_TABLE()
	vendguid = instance.VendorGuid

	# parse guid string
	elems = [int(e, 16) for e in guid.split('-')]
	elems[3] = (elems[3] << 48) | elems[4]

	# populate vendor guid struct
	vendguid.Data1 = elems[0]
	vendguid.Data2 = elems[1]
	vendguid.Data3 = elems[2]

	for i, el in enumerate(to_byte_values(elems[3], 8)):
		vendguid.Data4[i] = el

	instance.VendorTable = table
	instance.saveTo(ql, ptr)

	# keep track of guid
	confs.append(guid)

	return EFI_SUCCESS
