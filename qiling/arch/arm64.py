#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM

from qiling import Qiling
from qiling.arch.arch import QlArch
from qiling.arch.arm64_const import *

class QlArchARM64(QlArch):
    def __init__(self, ql: Qiling):
        super().__init__(ql)

        reg_maps = (
            reg_map,
            reg_map_w
        )

        for reg_maper in reg_maps:
            self.ql.reg.expand_mapping(reg_maper)

        self.ql.reg.create_reverse_mapping()
        self.ql.reg.register_sp(reg_map["sp"])
        self.ql.reg.register_pc(reg_map["pc"])

    # get initialized unicorn engine
    def get_init_uc(self) -> Uc:
        return Uc(UC_ARCH_ARM64, UC_MODE_ARM)

    def enable_vfp(self):
        self.ql.reg.cpacr_el1 = self.ql.reg.cpacr_el1 | 0x300000
