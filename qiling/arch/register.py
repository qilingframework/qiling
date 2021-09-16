#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Any, Mapping, MutableMapping, Union

from qiling import Qiling

class QlRegisterManager:
    """This class exposes the ql.reg features that allows you to directly access
    or assign values to CPU registers of a particular architecture.

    Registers exposed are listed in the *_const.py files in the respective
    arch directories and are mapped to Unicorn Engine's definitions
    """

    def __init__(self, ql: Qiling):
        self.register_mapping: MutableMapping[str, int] = {}
        self.reverse_mapping: Mapping[int, str] = {}
        self.ql = ql
        self.uc_pc = 0
        self.uc_sp = 0

    def __getattr__(self, name: str) -> Any:
        name = name.lower()

        # this is checked first to prevent endless recursion upon init
        if name == 'register_mapping':
            return super().__getattribute__(name)

        elif name in self.register_mapping:
            return self.ql.uc.reg_read(self.register_mapping[name])

        else:
            return super().__getattribute__(name)


    def __setattr__(self, name: str, value: Any):
        name = name.lower()

        # this is checked first to prevent endless recursion upon init
        if name == 'register_mapping':
            super().__setattr__(name, value)

        elif name in self.register_mapping:
            self.ql.uc.reg_write(self.register_mapping[name], value)

        else:
            super().__setattr__(name, value)


    def expand_mapping(self, extra: Mapping[str, int]) -> None:
        """Expand registers mapping with additional ones.
        """

        self.register_mapping.update(extra)


    # read register
    def read(self, register: Union[str, int]):
        """Read a register value.
        """

        if type(register) is str:
            register = self.register_mapping[register.lower()]

        return self.ql.uc.reg_read(register)


    def write(self, register: Union[str, int], value: int) -> None:
        """Write a register value.
        """

        if type(register) is str:
            register = self.register_mapping[register.lower()]

        return self.ql.uc.reg_write(register, value)


    def msr(self, msr: int, value: int = None):
        """Read or write a model-specific register (MSR) value.
        Intel architecture only
        """

        if value is None:
            return self.ql.uc.msr_read(msr)

        self.ql.uc.msr_write(msr, value)


    def save(self) -> MutableMapping[str, Any]:
        """Save CPU context.
        """

        return dict((reg, self.read(reg)) for reg in self.register_mapping)


    def restore(self, context: MutableMapping[str, Any] = {}) -> None:
        """Restore CPU context.
        """

        for reg, val in context.items():
            self.write(reg, val)


    # TODO: This needs to be implemented for all archs
    def bit(self, reg: Union[str, int]) -> int:
        """Get register size in bits.
        """

        if type(reg) is str:
            reg = self.register_mapping[reg]

        return self.ql.arch.get_reg_bit(reg)


    # Generic methods to get SP and IP across Arch's #
    # These functions should only be used if the     #
    # caller is dealing with multiple Arch's         #
    def register_sp(self, sp_id: int):
        self.uc_sp = sp_id


    def register_pc(self, pc_id: int):
        self.uc_pc = pc_id


    @property
    def arch_pc(self) -> int:
        return self.ql.uc.reg_read(self.uc_pc)


    @arch_pc.setter
    def arch_pc(self, value: int) -> None:
        return self.ql.uc.reg_write(self.uc_pc, value)

    @property
    def arch_pc_name(self) -> str:
        return self.reverse_mapping[self.uc_pc]

    @property
    def arch_sp(self) -> int:
        return self.ql.uc.reg_read(self.uc_sp)


    @arch_sp.setter
    def arch_sp(self, value: int) -> None:
        return self.ql.uc.reg_write(self.uc_sp, value)


    def create_reverse_mapping(self):
        self.reverse_mapping = {v:k for k, v in self.register_mapping.items()}
