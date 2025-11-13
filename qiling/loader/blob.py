#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.loader.loader import QlLoader, Image


class QlLoaderBLOB(QlLoader):
    def __init__(self, ql: Qiling):
        super().__init__(ql)

        self.load_address = 0

    def run(self):
        self.load_address = self.ql.os.load_address
        self.entry_point = self.ql.os.entry_point

        code_begins = self.load_address
        code_size = self.ql.os.code_ram_size
        code_ends = code_begins + code_size

        self.ql.mem.map(code_begins, code_size, info="[code]")
        self.ql.mem.write(code_begins, self.ql.code)

        # allow image-related functionalities
        self.images.append(Image(code_begins, code_ends, 'blob_code'))

        # FIXME: stack pointer should be a configurable profile setting
        self.ql.arch.regs.arch_sp = code_ends - 0x1000
