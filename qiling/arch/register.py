#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

class QlRegisterManager:
    def __init__(self, ql):
        self.ql = ql


    def rw(self, register_str, value):
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

    # ql.reg.pc - PC register value getter
    @property
    def pc(self):
        return self.ql.arch.get_pc()

    # ql.reg.pc - PC register value setter
    @pc.setter
    def pc(self, value):
        self.ql.arch.set_pc(value)

    # ql.reg.sp - SP register value getter
    @property
    def sp(self):
        return self.ql.arch.get_sp()

    # ql.reg.sp - SP register value setter
    @sp.setter
    def sp(self, value):
        self.ql.arch.set_sp(value)