from abc import ABC, abstractmethod
from typing import Any, Mapping, Dict, MutableSequence, Optional, Tuple, Type

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
        self.protocols: Dict[int, Dict[str, int]] = {}
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

    def install_protocol(self, proto_desc: Mapping, handle: int, address: Optional[int] = None, from_hook: bool = False):
        guid = proto_desc['guid']

        if handle not in self.protocols:
            self.protocols[handle] = {}

        if guid in self.protocols[handle]:
            self.ql.log.warning(f'a protocol with guid {guid} is already installed')

        if address is None:
            struct_class = proto_desc['struct']
            address = self.heap.alloc(struct_class.sizeof())

        instance = utils.init_struct(self.ql, address, proto_desc)
        instance.save_to(self.ql.mem, address)

        self.protocols[handle][guid] = address
        return self.notify_protocol(handle, guid, address, from_hook)

    def notify_protocol(self, handle: int, protocol: str, interface: int, from_hook: bool):
        for (event_id, event_dic) in self.ql.loader.events.items():
            if event_dic['Guid'] == protocol:
                if event_dic['CallbackArgs'] is None:
                    # To support smm notification, we use None for CallbackArgs on SmmRegisterProtocolNotify
                    # and update it here.
                    guid = utils.str_to_guid(protocol)
                    guid_ptr = self.heap.alloc(guid.sizeof())
                    guid.save_to(self.ql.mem, guid_ptr)

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

        # registered sw smi handlers
        self.swsmi_handlers: Mapping[int, Tuple[int, Mapping]] = {}


class UefiConfTable:
    def __init__(self, ql: Qiling, systbl_type: Type[STRUCT], fname_arrptr: str, fname_nitems: str):
        self.ql = ql

        self.__arrptr_off = systbl_type.offsetof(fname_arrptr)
        self.__nitems_off = systbl_type.offsetof(fname_nitems)

    @property
    @abstractmethod
    def system_table(self) -> int:
        pass

    @property
    def baseptr(self) -> int:
        addr = self.system_table + self.__arrptr_off

        return self.ql.mem.read_ptr(addr)

    @property
    def nitems(self) -> int:
        addr = self.system_table + self.__nitems_off

        return self.ql.mem.read_ptr(addr)	# UINTN

    @nitems.setter
    def nitems(self, value: int):
        addr = self.system_table + self.__nitems_off

        self.ql.mem.write_ptr(addr, value)

    def install(self, guid: str, table: int):
        ptr = self.find(guid)

        if ptr is None:
            ptr = self.baseptr + self.nitems * EFI_CONFIGURATION_TABLE.sizeof()
            self.nitems += 1

        EFI_CONFIGURATION_TABLE(
            VendorGuid = utils.str_to_guid(guid),
            VendorTable = table
        ).save_to(self.ql.mem, ptr)

    def find(self, guid: str) -> Optional[int]:
        ptr = self.baseptr
        nitems = self.nitems
        efi_guid = utils.str_to_guid(guid)

        for _ in range(nitems):
            entry = EFI_CONFIGURATION_TABLE.load_from(self.ql.mem, ptr)

            if utils.CompareGuid(entry.VendorGuid, efi_guid):
                return ptr

            ptr += EFI_CONFIGURATION_TABLE.sizeof()

        return None

    def get_vendor_table(self, guid: str) -> Optional[int]:
        ptr = self.find(guid)

        if ptr is not None:
            entry = EFI_CONFIGURATION_TABLE.load_from(self.ql.mem, ptr)

            return entry.VendorTable.value

        # not found
        return None


class DxeConfTable(UefiConfTable):
    def __init__(self, ql: Qiling):
        super().__init__(ql, EFI_SYSTEM_TABLE, 'ConfigurationTable', 'NumberOfTableEntries')

    @property
    def system_table(self) -> int:
        return self.ql.loader.gST


class SmmConfTable(UefiConfTable):
    def __init__(self, ql: Qiling):
        super().__init__(ql, EFI_SMM_SYSTEM_TABLE2, 'SmmConfigurationTable', 'NumberOfTableEntries')

    @property
    def system_table(self) -> int:
        return self.ql.loader.gSmst
