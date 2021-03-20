#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from abc import ABC, abstractmethod

from capstone import Cs
from keystone import Ks

from . import utils
from qiling import Qiling
from qiling.const import QL_ARCH

class QlArch(ABC):
    def __init__(self, ql: Qiling):
        self.ql = ql

    # ql.init_Uc - initialized unicorn engine
    @property
    def init_uc(self):
        return self.ql.arch.get_init_uc()


    # push value to stack
    @abstractmethod
    def stack_push(self, data: int) -> int:
        pass


    # pop value to stack
    @abstractmethod
    def stack_pop(self) -> int:
        pass


    # write stack value
    @abstractmethod
    def stack_write(self, offset: int, data: int) -> None:
        pass


    #  read stack value
    @abstractmethod
    def stack_read(self, offset: int) -> int:
        pass
 

       # set PC
    def set_pc(self, address: int):
        self.ql.reg.arch_pc = address


    # get PC
    def get_pc(self) -> int:
        return self.ql.reg.arch_pc


    # set stack pointer
    def set_sp(self, address: int):
        self.ql.reg.arch_sp = address


    # get stack pointer
    def get_sp(self) -> int:
        return self.ql.reg.arch_sp 


    # Unicorn's CPU state save
    def context_save(self):
        return self.ql.uc.context_save()


    # Unicorn's CPU state restore method
    def context_restore(self, saved_context):
        self.ql.uc.context_restore(saved_context)


    def create_disassembler(self) -> Cs:
        if self.ql.archtype in (QL_ARCH.ARM, QL_ARCH.ARM_THUMB):
            reg_cpsr = self.ql.reg.cpsr
        else:
            reg_cpsr = None
        return utils.ql_create_disassembler(self.ql.archtype, self.ql.archendian, reg_cpsr)


    def create_assembler(self) -> Ks:
        if self.ql.archtype in (QL_ARCH.ARM, QL_ARCH.ARM_THUMB):
            reg_cpsr = self.ql.reg.cpsr
        else:
            reg_cpsr = None
        return utils.ql_create_assembler(self.ql.archtype, self.ql.archendian, reg_cpsr)
