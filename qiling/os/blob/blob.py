#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.cc import QlCC, intel, arm, mips, riscv, ppc
from qiling.const import QL_ARCH, QL_OS
from qiling.os.fcall import QlFunctionCall
from qiling.os.os import QlOs

class QlOsBlob(QlOs):
    """ QlOsBlob for bare barines.

    For bare binary such as u-boot, it's ready to be mapped and executed directly,
    where there is(may be) no concept of os? Currently, some functionalities such as
    resolve_fcall_params(), heap or add_fs_mapper() are based on os. To keep the
    consistence of api usage, QlOsBlob is introduced and placed at its loader temporarily.
    """

    type = QL_OS.BLOB

    def __init__(self, ql: Qiling):
        super(QlOsBlob, self).__init__(ql)

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
        if self.ql.entry_point:
            self.entry_point = self.ql.entry_point

        self.exit_point = self.ql.loader.load_address + len(self.ql.code)
        if self.ql.exit_point:
            self.exit_point = self.ql.exit_point

        self.ql.emu_start(self.entry_point, self.exit_point, self.ql.timeout, self.ql.count)
