#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn import Uc, UC_ARCH_MIPS, UC_MODE_MIPS32, UC_MODE_BIG_ENDIAN, UC_MODE_LITTLE_ENDIAN

from qiling import Qiling
from qiling.const import QL_ENDIAN
from qiling.arch.arch import QlArch
from qiling.arch.mips_const import *

class QlArchMIPS(QlArch):
    def __init__(self, ql: Qiling):
        super().__init__(ql)

        reg_maps = (
            reg_map,
            reg_map_afpr128
        )

        for reg_maper in reg_maps:
            self.ql.reg.expand_mapping(reg_maper)

        self.ql.reg.create_reverse_mapping()
        self.ql.reg.register_sp(reg_map["sp"])
        self.ql.reg.register_pc(reg_map["pc"])

    # get initialized unicorn engine
    def get_init_uc(self) -> Uc:
        endian = {
            QL_ENDIAN.EB: UC_MODE_BIG_ENDIAN,
            QL_ENDIAN.EL: UC_MODE_LITTLE_ENDIAN
        }[self.ql.archendian]

        return Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + endian)