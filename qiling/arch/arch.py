#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from abc import ABC, abstractmethod
import struct

class QlArch(ABC):
    def __init__(self, ql):
        self.ql = ql

    # ql.init_Uc - initialized unicorn engine
    @property
    def init_uc(self):
        return self.ql.arch.get_init_uc()


    # push value to stack
    @abstractmethod
    def stack_push(self, value):
        pass


    # pop value to stack
    @abstractmethod
    def stack_pop(self):
        pass


    # write stack value
    @abstractmethod
    def stack_write(self, value, data):
        pass


    #  read stack value
    @abstractmethod
    def stack_read(self, value):
        pass
 

       # set PC
    def set_pc(self, value):
        self.ql.reg.arch_pc = value


    # get PC
    def get_pc(self):
        return self.ql.reg.arch_pc


    # set stack pointer
    def set_sp(self, value):
        self.ql.reg.arch_sp = value


    # get stack pointer
    def get_sp(self):
        return self.ql.reg.arch_sp 


    # Unicorn's CPU state save
    def context_save(self):
        return self.ql.uc.context_save()


    # Unicorn's CPU state restore method
    def context_restore(self, saved_context):
        self.ql.uc.context_restore(saved_context)
