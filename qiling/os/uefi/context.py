import logging
from qiling.os.memory import QlMemoryHeap
from qiling.os.uefi.utils import init_struct

class UefiContext:
	def __init__(self, ql):
		self.ql = ql
		self.heap = None
		self.protocols = {}

	def init_heap(self, base, size):
		self.heap = QlMemoryHeap(self.ql, base, base + size)

	def init_stack(self, base, size):
		self.ql.mem.map(base, size)

	def install_protocol(self, proto_desc, handle, address=None):
		guid = proto_desc['guid']

		if handle not in self.protocols:
			self.protocols[handle] = {}

		if guid in self.protocols[handle]:
			logging.warning(f'a protocol with guid {guid} is already installed')

		if address is None:
			struct_class = proto_desc['struct']
			address = self.heap.alloc(struct_class.sizeof())

		instance = init_struct(self.ql, address, proto_desc)
		instance.saveTo(self.ql, address)

		self.protocols[handle][guid] = address

class SmmContext(UefiContext):
	def __init__(self, ql):
		super(SmmContext, self).__init__(ql)

		# assume tseg is inaccessible to non-smm
		self.tseg_open = False

		# assume tseg is locked
		self.tseg_locked = True

		self.swsmi_handlers = []
