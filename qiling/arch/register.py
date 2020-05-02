#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

class QlRegisterManager():
    def __init__(self, ql):
        self.register_mapping = {}
        self.ql = ql

    def __getattribute__(self, name):
        if name in ("register_mapping", "ql"):
            return super(QlRegisterManager, self).__getattribute__(name)
        
        if name in self.register_mapping:
            return self.ql.uc.reg_read(self.register_mapping[name])

        return super(QlRegisterManager, self).__getattribute__(name)

    def __setattr__(self, name, value):
        if name in ("register_mapping", "ql"):
            super(QlRegisterManager, self).__setattr__(name, value)

        if name in self.register_mapping:
            self.ql.uc.reg_write(self.register_mapping[name], value)
        else:
            super(QlRegisterManager, self).__setattr__(name, value)

    def expand_mapping(self, expanded_map):
        self.register_mapping = {**self.register_mapping, **expanded_map}


    def rw(self, register_str, value):
        if type(register_str) == str:
            register_str = register_str.lower()

        if register_str is not None and value is None:
            return self.ql.arch.get_register(register_str)
        elif register_str is not None and value is not None:
            return self.ql.arch.set_register(register_str, value)

    def msr(self, msr, addr= None):
        if not addr:
            return self.ql.uc.msr_read(msr)
        else:
            self.ql.uc.msr_write(msr, addr)
    
    # ql.reg.store - store all register
    def store(self):
        reg_dict = {}
        for reg in self.ql.reg.table:
            self.ql.reg.name = reg
            reg_v = self.rw(self.ql.reg.name, value = None)
            reg_dict[self.ql.reg.name] = reg_v
        return reg_dict

    # ql.reg.restore - restore all stored register
    def restore(self, value = {}):
        for reg in self.ql.reg.table:
            self.ql.reg.name = reg
            reg_v= value[self.ql.reg.name]
            self.rw(self.ql.reg.name, reg_v)


    # ql.reg.bit() - Register bit
    def bit(self, uc_reg):
        return self.ql.arch.get_reg_bit(uc_reg)
        
    # ql.reg.name_pc - PC register name getter
    @property
    def name_pc(self):
        return self.ql.arch.get_name_pc()


    # ql.reg.name_sp - SP register name getter
    @property
    def name_sp(self):
        return self.ql.arch.get_name_sp()

    # ql.reg.tables - Register table getter
    @property
    def table(self):
        return self.ql.arch.get_reg_table()

    # ql.reg.name - Register name converter getter
    @property
    def name(self):
        return self.ql.arch.get_reg_name_str(self.uc_reg_name)

    # ql.reg.name - Register name converter setter
    @name.setter
    def name(self, uc_reg):
        self.uc_reg_name = uc_reg