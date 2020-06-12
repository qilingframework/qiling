#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

class QlRegisterManager():
    """
    This class exposes the ql.reg features that allows you to directly access
    or assign values to CPU registers of a particular architecture.

    Registers exposed are listed in the *_const.py files in the respective
    arch directories and are mapped to Unicorn Engine's definitions
    """
    def __init__(self, ql):
        self.register_mapping = {}
        self.ql = ql
        self.uc_pc = 0
        self.uc_sp = 0


    def __getattribute__(self, name):
        if name in ("register_mapping", "ql", "uc_pc", "uc_sp"):
            return super(QlRegisterManager, self).__getattribute__(name)
        
        if name in self.register_mapping:
            return self.ql.uc.reg_read(self.register_mapping[name])

        return super(QlRegisterManager, self).__getattribute__(name)


    def __setattr__(self, name, value):
        if name in ("register_mapping", "ql", "uc_pc", "uc_sp"):
            super(QlRegisterManager, self).__setattr__(name, value)

        if name in self.register_mapping:
            self.ql.uc.reg_write(self.register_mapping[name], value)
        else:
            super(QlRegisterManager, self).__setattr__(name, value)


    def expand_mapping(self, expanded_map):
        self.register_mapping = {**self.register_mapping, **expanded_map}


    # read register
    def read(self, register):
        if isinstance(register, str):
            register = self.register_mapping.get(register.lower(), None)
        return self.ql.uc.reg_read(register)


    def write(self, register, value):
        if isinstance(register, str):
            register = self.register_mapping.get(register.lower(), None) 
        return self.ql.uc.reg_write(register, value)


    def msr(self, msr, addr= None):
        if not addr:
            return self.ql.uc.msr_read(msr)
        else:
            self.ql.uc.msr_write(msr, addr)


    # ql.reg.save
    def save(self):
        reg_dict = {}
        for reg in self.register_mapping:
            reg_v = self.read(reg)
            reg_dict[reg] = reg_v
        return reg_dict


    # ql.reg.restore
    def restore(self, value = {}):
        for reg in self.register_mapping:
            reg_v= value[reg]
            self.write(reg, reg_v)


    # ql.reg.bit() - Register bit
    #FIXME: This needs to be implemented for all archs
    def bit(self, uc_reg):
        return self.ql.arch.get_reg_bit(uc_reg)


    # Generic methods to get SP and IP across Arch's #
    # These functions should only be used if the     #
    # caller is dealing with multiple Arch's         #
    def register_sp(self, sp_id):
        self.uc_sp = sp_id


    def register_pc(self, pc_id):
        self.uc_pc = pc_id


    @property
    def arch_pc(self):
        return self.ql.uc.reg_read(self.uc_pc)


    @arch_pc.setter
    def arch_pc(self, value):
        return self.ql.uc.reg_write(self.uc_pc, value)


    @property
    def arch_sp(self):
        return self.ql.uc.reg_read(self.uc_sp)


    @arch_sp.setter
    def arch_sp(self, value):
        return self.ql.uc.reg_write(self.uc_sp, value)


    def get_reg_name(self, uc_reg_name):
        return self.register_mapping.get(uc_reg_name, None)


    def create_reverse_mapping(self):
        reversed_mapping = {v:k for k, v in self.register_mapping.items()}
        self.expand_mapping(reversed_mapping)
