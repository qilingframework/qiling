from abc import ABC
from typing import Mapping, Tuple

from qiling import Qiling
from qiling.os.memory import QlMemoryHeap
from qiling.os.uefi.utils import init_struct, update_struct, str_to_guid, execute_protocol_notifications, signal_event
from qiling.os.uefi.UefiSpec import EFI_CONFIGURATION_TABLE, EFI_SYSTEM_TABLE
from qiling.os.uefi.smst import EFI_SMM_SYSTEM_TABLE2

class UefiContext(ABC):
	def __init__(self, ql: Qiling):
		self.ql = ql
		self.heap = None
		self.protocols = {}

		# These members must be initialized before attempting to install a configuration table.
		self.conf_table_array = []
		self.conf_table_array_ptr = 0
		self.conf_table_data_ptr = 0
		self.conf_table_data_next_ptr = 0

	def init_heap(self, base: int, size: int):
		self.heap = QlMemoryHeap(self.ql, base, base + size)

	def init_stack(self, base: int, size: int):
		self.ql.mem.map(base, size)

	def install_protocol(self, proto_desc: Mapping, handle, address: int = None, from_hook: bool = False):
		guid = proto_desc['guid']

		if handle not in self.protocols:
			self.protocols[handle] = {}

		if guid in self.protocols[handle]:
			self.ql.log.warning(f'a protocol with guid {guid} is already installed')

		if address is None:
			struct_class = proto_desc['struct']
			address = self.heap.alloc(struct_class.sizeof())

		instance = init_struct(self.ql, address, proto_desc)
		instance.saveTo(self.ql, address)

		self.protocols[handle][guid] = address
		return self.notify_protocol(handle, guid, address, from_hook)

	def notify_protocol(self, handle, protocol, interface, from_hook):
		for (event_id, event_dic) in self.ql.loader.events.items():
			if event_dic['Guid'] == protocol:
				if event_dic['CallbackArgs'] == None:
					# To support smm notification, we use None for CallbackArgs on SmmRegisterProtocolNotify 
					# and updare it here.
					guid = str_to_guid(protocol)
					guid_ptr = self.heap.alloc(guid.sizeof())
					guid.saveTo(self.ql, guid_ptr)
					event_dic['CallbackArgs'] = [guid_ptr, interface, handle]
				# The event was previously registered by 'RegisterProtocolNotify'.
				signal_event(self.ql, event_id)
		return execute_protocol_notifications(self.ql, from_hook)

	def install_configuration_table(self, guid: str, table: int):
		guid = guid.lower()
		confs = self.conf_table_array

		# find configuration table entry by guid. if found, idx would be set to the entry index
		# in the array. if not, idx would be set to one past end of array
		if guid not in confs:
			confs.append(guid)

		idx = confs.index(guid)
		ptr = self.conf_table_array_ptr + (idx * EFI_CONFIGURATION_TABLE.sizeof())

		instance = EFI_CONFIGURATION_TABLE()
		instance.VendorGuid = str_to_guid(guid)
		instance.VendorTable = table
		instance.saveTo(self.ql, ptr)

class DxeContext(UefiContext):
	def install_configuration_table(self, guid: str, table: int):
		super().install_configuration_table(guid, table)

		# Update number of configuration table entries in the ST.
		with update_struct(EFI_SYSTEM_TABLE, self.ql, self.ql.loader.gST) as gST:
			gST.NumberOfTableEntries = len(self.conf_table_array)

class SmmContext(UefiContext):
	def __init__(self, ql):
		super(SmmContext, self).__init__(ql)

		# assume tseg is inaccessible to non-smm
		self.tseg_open = False

		# assume tseg is locked
		self.tseg_locked = True

		# registered sw smi handlers
		self.swsmi_handlers: Mapping[int, Tuple[int, Mapping]] = {}

	def install_configuration_table(self, guid: str, table: int):
		super().install_configuration_table(guid, table)

		# Update number of configuration table entries in the SMST.
		with update_struct(EFI_SMM_SYSTEM_TABLE2, self.ql, self.ql.loader.gSmst) as gSmst:
			gSmst.NumberOfTableEntries = len(self.conf_table_array)
