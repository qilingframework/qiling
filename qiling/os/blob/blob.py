#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.cc import QlCC, intel, arm, mips, riscv, ppc
from qiling.const import QL_ARCH, QL_OS
from qiling.os.fcall import QlFunctionCall
from qiling.os.os import QlOs
from qiling.os.memory import QlMemoryHeap


class QlOsBlob(QlOs):
    """ QlOsBlob for bare barines.

    For bare binary such as u-boot, it's ready to be mapped and executed directly,
    where there is(may be) no concept of os? Currently, some functionalities such as
    resolve_fcall_params(), heap or add_fs_mapper() are based on os. To keep the
    consistence of api usage, QlOsBlob is introduced and placed at its loader temporarily.
    """

    type = QL_OS.BLOB

    def __init__(self, ql: Qiling):
        super().__init__(ql)

        self.ql = ql

        cc: QlCC = {
            QL_ARCH.X86     : intel.cdecl,
            QL_ARCH.X8664   : intel.amd64,
            QL_ARCH.ARM     : arm.aarch32,
            QL_ARCH.ARM64   : arm.aarch64,
            QL_ARCH.MIPS    : mips.mipso32,
            QL_ARCH.RISCV   : riscv.riscv,
            QL_ARCH.RISCV64 : riscv.riscv,
            QL_ARCH.PPC     : ppc.ppc,
        }[ql.arch.type](ql.arch)

        self.fcall = QlFunctionCall(ql, cc)

    def run(self):
        # if entry point was set explicitly, override the default one
        if self.ql.entry_point is not None:
            self.entry_point = self.ql.entry_point

        self.exit_point = self.load_address + len(self.ql.code)

        # if exit point was set explicitly, override the default one
        if self.ql.exit_point is not None:
            self.exit_point = self.ql.exit_point
        
        # if heap info is provided in profile, create heap
        heap_base = self.profile.getint('CODE', 'heap_address', fallback=None)
        heap_size = self.profile.getint('CODE', 'heap_size', fallback=None)
        if heap_base is not None and heap_size is not None:
            self.heap = QlMemoryHeap(self.ql, heap_base, heap_base + heap_size)
        
        self.ql.emu_start(self.entry_point, self.exit_point, self.ql.timeout, self.ql.count)
