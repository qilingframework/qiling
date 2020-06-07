#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import struct

class QlArch:
    def __init__(self, ql):
        self.ql = ql

    # ql.init_Uc - initialized unicorn engine
    @property
    def init_uc(self):
        return self.ql.arch.get_init_uc()


    # push value to stack
    def stack_push(self, value):
        pass


    # pop value to stack
    def stack_pop(self):
        pass


    # write stack value
    def stack_write(self, value, data):
        pass


    #  read stack value
    def stack_read(self, value):
        pass


    # set PC
    def set_pc(self, value):
        pass


    # get PC
    def get_pc(self):
        pass


    # set stack pointer
    def set_sp(self, value):
        pass


    # get stack pointer
    def get_sp(self):
        pass


    # get stack pointer register
    def get_name_sp(self):
        pass


    # get PC register
    def get_name_pc(self):
        pass


    # get PC register
    def get_reg_table(self):
        pass


    # get register name
    def get_reg_name_str(self):
        pass


    # set register name
    def set_reg_name_str(self, uc_reg):
        pass
   
   
    def addr_to_str(self, addr, short=False, endian="big"):
        if self.ql.archbit == 64 and short == False:
            addr = (hex(int.from_bytes(struct.pack('<Q', addr), byteorder=endian)))
            addr = '{:0>16}'.format(addr[2:])
        elif self.ql.archbit == 32 or short == True:
            addr = (hex(int.from_bytes(struct.pack('<I', addr), byteorder=endian)))
            addr = ('{:0>8}'.format(addr[2:]))
        addr = str(addr)    
        return addr


    # Unicorn's CPU state save
    def context_save(self):
        return self.ql.uc.context_save()


    # Unicorn's CPU state restore method
    def context_restore(self, saved_context):
        self.ql.uc.context_restore(saved_context)        