from abc import ABC, abstractmethod
from typing import Any, Mapping, MutableSequence, Optional, Tuple

from qiling import Qiling
from qiling.os.memory import QlMemoryHeap
from qiling.os.uefi.ProcessorBind import STRUCT, CPU_STACK_ALIGNMENT
from qiling.os.uefi.UefiSpec import EFI_CONFIGURATION_TABLE, EFI_SYSTEM_TABLE
from qiling.os.uefi.smst import EFI_SMM_SYSTEM_TABLE2
from qiling.os.uefi import utils

class UefiContext(ABC):
	def __init__(self, ql: Qiling):
		self.ql = ql
		self.heap: QlMemoryHeap
		self.top_of_stack: int
		self.protocols = {}
		self.loaded_image_protocol_modules: MutableSequence[int] = []
		self.next_image_base: int

		# These members must be initialized before attempting to install a configuration table.
		self.conf_table_data_ptr = 0
		self.conf_table_data_next_ptr = 0

		self.conftable: UefiConfTable
		self.end_of_execution_ptr: int

	# TODO: implement save state
	def save(self) -> Mapping[str, Any]:
		return {}

	# TODO: implement restore state
	def restore(self, saved_state: Mapping[str, Any]):
		pass

	def init_heap(self, base: int, size: int):
		self.heap = QlMemoryHeap(self.ql, base, base + size)

	def init_stack(self, base: int, size: int):
		self.ql.mem.map(base, size, info='[stack]')
		self.top_of_stack = (base + size - 1) & ~(CPU_STACK_ALIGNMENT - 1)

	def install_protocol(self, proto_desc: Mapping, handle: int, address: int = None, from_hook: bool = False):
		guid = proto_desc['guid']

		if handle not in self.protocols:
			self.protocols[handle] = {}

		if guid in self.protocols[handle]:
			self.ql.log.warning(f'a protocol with guid {guid} is already installed')

		if address is None:
			struct_class = proto_desc['struct']
			address = self.heap.alloc(struct_class.sizeof())

		instance = utils.init_struct(self.ql, address, proto_desc)
		instance.saveTo(self.ql, address)

		self.protocols[handle][guid] = address
		return self.notify_protocol(handle, guid, address, from_hook)

	def notify_protocol(self, handle: int, protocol: str, interface: int, from_hook: bool):
		for (event_id, event_dic) in self.ql.loader.events.items():
			if event_dic['Guid'] == protocol:
				if event_dic['CallbackArgs'] == None:
					# To support smm notification, we use None for CallbackArgs on SmmRegisterProtocolNotify 
					# and updare it here.
					guid = utils.str_to_guid(protocol)
					guid_ptr = self.heap.alloc(guid.sizeof())
					guid.saveTo(self.ql, guid_ptr)

					event_dic['CallbackArgs'] = [guid_ptr, interface, handle]

				# The event was previously registered by 'RegisterProtocolNotify'.
				utils.signal_event(self.ql, event_id)

		return utils.execute_protocol_notifications(self.ql, from_hook)

class DxeContext(UefiContext):
	def __init__(self, ql: Qiling):
		super().__init__(ql)

		self.conftable = DxeConfTable(ql)

class SmmContext(UefiContext):
	def __init__(self, ql: Qiling):
		super().__init__(ql)

		self.conftable = SmmConfTable(ql)

		self.smram_base: int
		self.smram_size: int

		# assume tseg is inaccessible to non-smm
		self.tseg_open = False

		# assume tseg is locked
		self.tseg_locked = True

		# registered sw smi handlers
		self.swsmi_handlers: Mapping[int, Tuple[int, Mapping]] = {}

class UefiConfTable:
	_struct_systbl: STRUCT
	_fname_arrptr: str
	_fname_nitems: str

	def __init__(self, ql: Qiling):
		self.ql = ql

		self.__arrptr_off = self._struct_systbl.offsetof(self._fname_arrptr)
		self.__nitems_off = self._struct_systbl.offsetof(self._fname_nitems)

	@property
	@abstractmethod
	def system_table(self) -> int:
		pass

	@property
	def baseptr(self) -> int:
		addr = self.system_table + self.__arrptr_off

		return utils.read_int64(self.ql, addr)

	@property
	def nitems(self) -> int:
		addr = self.system_table + self.__nitems_off

		return utils.read_int64(self.ql, addr)	# UINTN

	@nitems.setter
	def nitems(self, value: int):
		addr = self.system_table + self.__nitems_off

		utils.write_int64(self.ql, addr, value)

	def install(self, guid: str, table: int):
		ptr = self.find(guid)
		append = ptr is None

		if append:
			ptr = self.baseptr + self.nitems * EFI_CONFIGURATION_TABLE.sizeof()
			append = True

		instance = EFI_CONFIGURATION_TABLE()
		instance.VendorGuid = utils.str_to_guid(guid)
		instance.VendorTable = table
		instance.saveTo(self.ql, ptr)

		if append:
			self.nitems += 1

	def find(self, guid: str) -> Optional[int]:
		ptr = self.baseptr
		nitems = self.nitems
		efi_guid = utils.str_to_guid(guid)

		for _ in range(nitems):
			entry = EFI_CONFIGURATION_TABLE.loadFrom(self.ql, ptr)

			if utils.CompareGuid(entry.VendorGuid, efi_guid):
				return ptr

			ptr += EFI_CONFIGURATION_TABLE.sizeof()

		return None

	def get_vendor_table(self, guid: str) -> Optional[int]:
		ptr = self.find(guid)

		if ptr is not None:
			entry = EFI_CONFIGURATION_TABLE.loadFrom(self.ql, ptr)

			return entry.VendorTable.value

		# not found
		return None

class DxeConfTable(UefiConfTable):
	_struct_systbl = EFI_SYSTEM_TABLE
	_fname_arrptr = 'ConfigurationTable'
	_fname_nitems = 'NumberOfTableEntries'

	@property
	def system_table(self) -> int:
		return self.ql.loader.gST

class SmmConfTable(UefiConfTable):
	_struct_systbl = EFI_SMM_SYSTEM_TABLE2
	_fname_arrptr = 'SmmConfigurationTable'
	_fname_nitems = 'NumberOfTableEntries'

	@property
	def system_table(self) -> int:
		return self.ql.loader.gSmst
