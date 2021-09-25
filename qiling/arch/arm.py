#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_MODE_THUMB, UC_MODE_BIG_ENDIAN
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from keystone import Ks, KS_ARCH_ARM, KS_MODE_ARM, KS_MODE_THUMB

from qiling import Qiling
from qiling.const import QL_ARCH, QL_ENDIAN
from qiling.arch.arch import QlArch
from qiling.arch.arm_const import *
from qiling.exception import QlErrorArch

class QlArchARM(QlArch):
    def __init__(self, ql: Qiling):
        super().__init__(ql)

        reg_maps = (
            reg_map,
        )

        for reg_maper in reg_maps:
            self.ql.reg.expand_mapping(reg_maper)

        self.ql.reg.register_sp(reg_map["sp"])
        self.ql.reg.register_pc(reg_map["pc"])

        self.arm_get_tls_addr = 0xFFFF0FE0

    # get initialized unicorn engine
    def get_init_uc(self) -> Uc:
        if self.ql.archendian == QL_ENDIAN.EB:
            mode = UC_MODE_ARM + UC_MODE_BIG_ENDIAN

        elif self.ql.archtype == QL_ARCH.ARM_THUMB:
            mode = UC_MODE_THUMB

        elif self.ql.archtype == QL_ARCH.ARM:
            mode = UC_MODE_ARM

        else:
            raise QlErrorArch(f'unsupported arch type {self.ql.archtype}')

        return Uc(UC_ARCH_ARM, mode)


    # get PC
    def get_pc(self) -> int:
        append = 1 if self.check_thumb() == UC_MODE_THUMB else 0

        return self.ql.reg.pc + append

    def __is_thumb(self) -> bool:
        cpsr_v = {
            QL_ENDIAN.EL : 0b100000,
            QL_ENDIAN.EB : 0b100000   # FIXME: should be: 0b000000
        }[self.ql.archendian]

        return bool(self.ql.reg.cpsr & cpsr_v)

    def create_disassembler(self) -> Cs:
        # note: we do not cache the disassembler instance; rather we refresh it
        # each time to make sure thumb mode is taken into account

        if self.ql.archtype == QL_ARCH.ARM:
            # FIXME: mode should take endianess into account
            mode = CS_MODE_THUMB if self.__is_thumb() else CS_MODE_ARM

        elif self.ql.archtype == QL_ARCH.ARM_THUMB:
            mode = CS_MODE_THUMB

        else:
            raise QlErrorArch(f'unexpected arch type {self.ql.archtype}')

        return Cs(CS_ARCH_ARM, mode)


    def create_assembler(self) -> Ks:
        # note: we do not cache the assembler instance; rather we refresh it
        # each time to make sure thumb mode is taken into account

        if self.ql.archtype == QL_ARCH.ARM:
            # FIXME: mode should take endianess into account
            mode = KS_MODE_THUMB if self.__is_thumb() else KS_MODE_ARM

        elif self.ql.archtype == QL_ARCH.ARM_THUMB:
            mode = KS_MODE_THUMB

        else:
            raise QlErrorArch(f'unexpected arch type {self.ql.archtype}')

        return Ks(KS_ARCH_ARM, mode)

    def enable_vfp(self) -> None:
        self.ql.reg.c1_c0_2 = self.ql.reg.c1_c0_2 | (0xf << 20)

        if self.ql.archendian == QL_ENDIAN.EB:
            self.ql.reg.fpexc = 0x40000000
            #self.ql.reg.fpexc = 0x00000040
        else:
            self.ql.reg.fpexc = 0x40000000

    def check_thumb(self):
        return UC_MODE_THUMB if self.__is_thumb() else UC_MODE_ARM
