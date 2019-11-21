#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 


class Arch:
    def __init__(self, ql):
        self.ql = ql


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
