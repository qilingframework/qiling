#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.cc import QlCC, intel, arm, mips
from qiling.const import QL_ARCH
from qiling.loader.loader import QlLoader
from qiling.os.fcall import QlFunctionCall
from qiling.os.memory import QlMemoryHeap
from qiling.os.os import QlOs


class QLOsBare(QlOs):
    """ QLOsBare for bare barines.

    For bare binary such as u-boot, it's ready to be mapped and executed directly,
    where there is(may be) no concept of os? Currently, some functionalities such as
    resolve_fcall_params(), heap or add_fs_mapper() are based on os. To keep the
    consistence of api usage, QLOsBare is introduced and placed at its loader temporarily.
    """
    def __init__(self, ql: Qiling):
        super(QLOsBare, self).__init__(ql)

        self.ql = ql

        cc: QlCC = {
            QL_ARCH.X86   : intel.cdecl,
            QL_ARCH.X8664 : intel.amd64,
            QL_ARCH.ARM   : arm.aarch32,
            QL_ARCH.ARM64 : arm.aarch64,
            QL_ARCH.MIPS  : mips.mipso32
        }[ql.archtype](ql)

        self.fcall = QlFunctionCall(ql, cc)

    def run(self):
        self.entry_point = self.ql.entry_point if self.ql.entry_point else self.ql.loader.load_address
        self.exit_point = self.ql.exit_point if self.ql.exit_point else self.ql.loader.load_address + len(self.ql.code)

        self.ql.emu_start(self.entry_point, self.exit_point, self.ql.timeout, self.ql.count)

class QlLoaderBLOB(QlLoader):
    def __init__(self, ql: Qiling):
        super().__init__(ql)

        self.load_address = 0

    def run(self):
        # setup bare os
        self.ql._os = QLOsBare(self.ql)

        self.load_address = self.ql.os.entry_point      # for consistency

        self.ql.mem.map(self.ql.os.entry_point, self.ql.os.code_ram_size, info="[code]")
        self.ql.mem.write(self.ql.os.entry_point, self.ql.code)

        heap_address = self.ql.os.entry_point + self.ql.os.code_ram_size
        heap_size = int(self.ql.os.profile.get("CODE", "heap_size"), 16)
        self.ql.os.heap = QlMemoryHeap(self.ql, heap_address, heap_address + heap_size)

        self.ql.reg.arch_sp = heap_address - 0x1000

        return
