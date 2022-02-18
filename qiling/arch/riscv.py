#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn import Uc, UC_ARCH_RISCV, UC_MODE_RISCV32
from capstone import Cs
from keystone import Ks

from qiling import Qiling
from qiling.arch.arch import QlArch
from qiling.arch.riscv_const import *
from qiling.exception import QlErrorNotImplemented


class QlArchRISCV(QlArch):
    def __init__(self, ql: Qiling):
        super().__init__(ql)

        reg_maps = (
            reg_map,
            reg_csr_map,
            reg_float_map,
        )

        for reg_maper in reg_maps:
            self.ql.reg.expand_mapping(reg_maper)
        self.ql.reg.register_sp(reg_map["sp"])
        self.ql.reg.register_pc(reg_map["pc"])

    # get initialized unicorn engine
    def get_init_uc(self) -> Uc:
        return Uc(UC_ARCH_RISCV, UC_MODE_RISCV32)

    def create_disassembler(self) -> Cs:
        try:
            from capstone import CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCVC
            return Cs(CS_ARCH_RISCV, CS_MODE_RISCV32 + CS_MODE_RISCVC)
        except ImportError:
            raise QlErrorNotImplemented("Capstone does not yet support riscv, upgrade to capstone 5.0")

    def create_assembler(self) -> Ks:
        raise QlErrorNotImplemented("Keystone does not yet support riscv")

    def enable_float(self):
        self.ql.reg.mstatus = self.ql.reg.mstatus | MSTATUS.FS_DIRTY

    def init_context(self):
        self.ql.reg.pc = 0x08000000
        
    def unicorn_exception_handler(self, ql, intno):
        if intno == 2:            
            ql.log.warning(f'[{hex(self.get_pc())}] Illegal instruction')
            
        else:
            raise QlErrorNotImplemented(f'Unhandled interrupt number ({intno})')
