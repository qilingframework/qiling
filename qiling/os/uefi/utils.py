#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import binascii

from uuid import UUID
from typing import Optional, Mapping
from contextlib import contextmanager

from qiling import Qiling
from qiling.os.uefi.const import EFI_SUCCESS
from qiling.os.uefi.ProcessorBind import STRUCT
from qiling.os.uefi.UefiSpec import EFI_CONFIGURATION_TABLE
from qiling.os.uefi.UefiBaseType import EFI_GUID

def signal_event(ql: Qiling, event_id: int) -> None:
	event = ql.loader.events[event_id]

	if not event["Set"]:
		event["Set"] = True
		notify_func = event["NotifyFunction"]
		callback_args = event["CallbackArgs"]

		ql.loader.notify_list.append((event_id, notify_func, callback_args))

def execute_protocol_notifications(ql: Qiling, from_hook: bool = False) -> bool:
	if not ql.loader.notify_list:
		return False

	next_hook = ql.loader.smm_context.heap.alloc(ql.pointersize)

	def __notify_next(ql: Qiling):
		if ql.loader.notify_list:
			event_id, notify_func, callback_args = ql.loader.notify_list.pop(0)
			ql.log.info(f'Notify event: id = {event_id}, (*{notify_func:#x})({", ".join(f"{a:#x}" for a in callback_args)})')

			ql.loader.call_function(notify_func, callback_args, next_hook)
		else:
			ql.log.info(f'Notify event: done')

			# the last item on the list has been notified; tear down this hook
			ql.loader.smm_context.heap.free(next_hook)
			hret.remove()

			ql.reg.rax = EFI_SUCCESS
			ql.reg.arch_sp += (4 * ql.pointersize)
			ql.reg.arch_pc = ql.stack_pop()

	hret = ql.hook_address(__notify_next, next_hook)

	# functions with more than 4 parameters expect the extra parameters to appear on
	# the stack. allocate room for another 4 parameters, in case one of the fucntions
	# will need it
	ql.reg.arch_sp -= (4 * ql.pointersize)

	# To avoid having two versions of the code the first notify function will also be called from the __notify_next hook.
	if from_hook:
		ql.stack_push(next_hook)
	else:
		ql.stack_push(ql.loader.end_of_execution_ptr)
		ql.reg.arch_pc = next_hook

	return True

def check_and_notify_protocols(ql: Qiling, from_hook: bool = False) -> bool:
	if ql.loader.notify_list:
		event_id, notify_func, notify_context = ql.loader.notify_list.pop(0)
		ql.log.info(f'Notify event: id = {event_id}, calling: {notify_func:#x} context: {notify_context}')

		if from_hook:
			# When running from a hook the caller pops the return address from the stack.
			# We need to push the address to the stack as opposed to setting it to the instruction pointer.
			ql.loader.call_function(0, notify_context, notify_func)
		else:
			ql.loader.call_function(notify_func, notify_context, ql.loader.end_of_execution_ptr)

		return True

	return False

def ptr_read8(ql: Qiling, addr: int) -> int:
	"""Read BYTE data from a pointer
	"""

	return ql.unpack8(ql.mem.read(addr, 1))

def ptr_write8(ql: Qiling, addr: int, val: int) -> None:
	"""Write BYTE data to a pointer
	"""

	ql.mem.write(addr, ql.pack8(val))

def ptr_read32(ql: Qiling, addr: int) -> int:
	"""Read DWORD data from a pointer
	"""

	return ql.unpack32(ql.mem.read(addr, 4))

def ptr_write32(ql: Qiling, addr: int, val: int) -> None:
	"""Write DWORD data to a pointer
	"""

	ql.mem.write(addr, ql.pack32(val))

def ptr_read64(ql: Qiling, addr: int) -> int:
	"""Read QWORD data from a pointer
	"""

	return ql.unpack64(ql.mem.read(addr, 8))

def ptr_write64(ql: Qiling, addr: int, val: int) -> None:
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

def init_struct(ql: Qiling, base: int, descriptor: Mapping):
	struct_class = descriptor['struct']
	struct_fields = descriptor.get('fields', [])

	isntance = struct_class()
	ql.log.info(f'Initializing {struct_class.__name__}')

	for name, value in struct_fields:
		if value is not None:
			# a method: hook this field
			if callable(value):
				p = base + struct_class.offsetof(name)

				setattr(isntance, name, p)
				ql.hook_address(value, p)

				ql.log.info(f' | {name:36s} {p:#010x}')

			# a value: set it
			else:
				setattr(isntance, name, value)

	ql.log.info(f'')

	return isntance

@contextmanager
def update_struct(cls: STRUCT, ql: Qiling, address: int):
	struct = cls.loadFrom(ql, address)

	try:
		yield struct
	finally:
		struct.saveTo(ql, address)

def str_to_guid(guid: str) -> EFI_GUID:
	"""Construct an EFI_GUID structure out of a plain GUID string.
	"""

	buff = UUID(hex=guid).bytes_le

	return EFI_GUID.from_buffer_copy(buff)

def CompareGuid(guid1: EFI_GUID, guid2: EFI_GUID) -> bool:
	return bytes(guid1) == bytes(guid2)

def install_configuration_table(context, key: str, table: int):
	"""Create a new Configuration Table entry and add it to the list.

	Args:
		ql    : Qiling instance
		key   : profile section name that holds the entry data
		table : address of configuration table data; if None, data will be read
		        from profile section into memory
	"""

	cfgtable = context.ql.os.profile[key]
	guid = cfgtable['Guid']

	# if pointer to table data was not specified, load table data
	# from profile and have table pointing to it
	if table is None:
		data = binascii.unhexlify(cfgtable['TableData'])
		table = context.conf_table_data_next_ptr

		context.ql.mem.write(table, data)
		context.conf_table_data_next_ptr += len(data)

	context.install_configuration_table(guid, table)

def GetEfiConfigurationTable(context, guid: str) -> Optional[int]:
	"""Find a configuration table by its GUID.
	"""

	guid = guid.lower()
	confs = context.conf_table_array

	if guid in confs:
		idx = confs.index(guid)
		ptr = context.conf_table_array_ptr + (idx * EFI_CONFIGURATION_TABLE.sizeof())

		return ptr

	# not found
	return None
