#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import binascii

from uuid import UUID
from typing import Optional, Mapping

from qiling import Qiling
from qiling.os.uefi.const import EFI_SUCCESS
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

	next_hook = ql.loader.context.heap.alloc(ql.arch.pointersize)

	def __notify_next(ql: Qiling):
		# discard previous callback's shadow space
		ql.arch.regs.arch_sp += (4 * ql.arch.pointersize)

		if ql.loader.notify_list:
			event_id, notify_func, callback_args = ql.loader.notify_list.pop(0)
			ql.log.info(f'Notify event: id = {event_id}, (*{notify_func:#x})({", ".join(f"{a:#x}" for a in callback_args)})')

			ql.loader.call_function(notify_func, callback_args, next_hook)
		else:
			ql.log.info(f'Notify event: done')

			# the last item on the list has been notified; tear down this hook
			ql.loader.context.heap.free(next_hook)
			hret.remove()

			ql.arch.regs.rax = EFI_SUCCESS
			ql.arch.regs.arch_pc = ql.stack_pop()

	hret = ql.hook_address(__notify_next, next_hook)

	# __notify_next unwinds the previous callback shadow space allocated by call_function. however, on its first invocation
	# there is no such shadow space. to maintain stack consistency we set here a bogus shadow space that may be discarded
	# safely
	ql.arch.regs.arch_sp -= (4 * ql.arch.pointersize)

	# To avoid having two versions of the code the first notify function will also be called from the __notify_next hook.
	if from_hook:
		ql.stack_push(next_hook)
	else:
		ql.stack_push(ql.loader.context.end_of_execution_ptr)
		ql.arch.regs.arch_pc = next_hook

	return True

def ptr_read8(ql: Qiling, addr: int) -> int:
	"""Read BYTE data from a pointer
	"""

	return ql.mem.read_ptr(addr, 1)

def ptr_write8(ql: Qiling, addr: int, val: int) -> None:
	"""Write BYTE data to a pointer
	"""

	ql.mem.write_ptr(addr, val, 1)

def ptr_read16(ql: Qiling, addr: int) -> int:
	"""Read WORD data from a pointer
	"""

	return ql.mem.read_ptr(addr, 2)

def ptr_write16(ql: Qiling, addr: int, val: int) -> None:
	"""Write WORD data to a pointer
	"""

	ql.mem.write_ptr(addr, val, 2)

def ptr_read32(ql: Qiling, addr: int) -> int:
	"""Read DWORD data from a pointer
	"""

	return ql.mem.read_ptr(addr, 4)

def ptr_write32(ql: Qiling, addr: int, val: int) -> None:
	"""Write DWORD data to a pointer
	"""

	ql.mem.write_ptr(addr, val, 4)

def ptr_read64(ql: Qiling, addr: int) -> int:
	"""Read QWORD data from a pointer
	"""

	return ql.mem.read_ptr(addr, 8)

def ptr_write64(ql: Qiling, addr: int, val: int) -> None:
	"""Write QWORD data to a pointer
	"""

	ql.mem.write_ptr(addr, val, 8)

# backward comptability
read_int8   = ptr_read8
write_int8  = ptr_write8
read_int16  = ptr_read16
write_int16 = ptr_write16
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

def str_to_guid(guid: str) -> EFI_GUID:
	"""Construct an EFI_GUID structure out of a plain GUID string.
	"""

	buff = UUID(hex=guid).bytes_le

	return EFI_GUID.from_buffer_copy(buff)

def CompareGuid(guid1: EFI_GUID, guid2: EFI_GUID) -> bool:
	return bytes(guid1) == bytes(guid2)

def install_configuration_table(context, key: str, table: Optional[int]):
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

	context.conftable.install(guid, table)

def GetEfiConfigurationTable(context, guid: str) -> Optional[int]:
	"""Find a configuration table by its GUID.
	"""

	return context.conftable.get_vendor_table(guid)