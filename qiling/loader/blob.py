#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.loader.loader import QlLoader
from qiling.os.memory import QlMemoryHeap

class QlLoaderBLOB(QlLoader):
    def __init__(self, ql: Qiling):
        super().__init__(ql)

        self.load_address = 0

    def run(self):
        self.load_address = self.ql.os.entry_point      # for consistency

        self.ql.mem.map(self.ql.os.entry_point, self.ql.os.code_ram_size, info="[code]")
        self.ql.mem.write(self.ql.os.entry_point, self.ql.code)

        heap_address = self.ql.os.entry_point + self.ql.os.code_ram_size
        heap_size = int(self.ql.os.profile.get("CODE", "heap_size"), 16)
        self.ql.os.heap = QlMemoryHeap(self.ql, heap_address, heap_address + heap_size)

        self.ql.arch.regs.arch_sp = heap_address - 0x1000

        return
