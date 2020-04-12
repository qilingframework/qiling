#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

##############################################
# These are part of the core.py Qiling class #
# Functions below are imported at runtime    #
##############################################
from unicorn import *
from unicorn.x86_const import *
from .utils import catch_KeyboardInterrupt

def hook_code(self, callback, user_data=None, begin=1, end=0):
    @catch_KeyboardInterrupt(self)
    def _callback(uc, addr, size, pack_data):
        # unpack what we packed for hook_add()
        user_data, callback = pack_data
        if user_data:
            callback(self, addr, size, user_data)
        else:
            # callback does not require user_data
            callback(self, addr, size)

    # pack user_data & callback for wrapper _callback
    self.uc.hook_add(UC_HOOK_CODE, _callback, (user_data, callback), begin, end)


def hook_intr(self, callback, user_data=None, begin=1, end=0):
    @catch_KeyboardInterrupt(self)
    def _callback(uc, intno, pack_data):
        # unpack what we packed for hook_add()
        user_data, callback = pack_data
        if user_data:
            callback(self, intno, user_data)
        else:
            # callback does not require user_data
            callback(self, intno)

    # pack user_data & callback for wrapper _callback
    self.uc.hook_add(UC_HOOK_INTR, _callback, (user_data, callback), begin, end)


def hook_block(self, callback, user_data=None, begin=1, end=0):
    @catch_KeyboardInterrupt(self)
    def _callback(uc, addr, size, pack_data):
        # unpack what we packed for hook_add()
        user_data, callback = pack_data
        if user_data:
            callback(self, addr, size, user_data)
        else:
            # callback does not require user_data
            callback(self, addr, size)

    # pack user_data & callback for wrapper _callback
    self.uc.hook_add(UC_HOOK_BLOCK, _callback, (user_data, callback), begin, end)

def hook_mem_unmapped(self, callback, user_data=None, begin=1, end=0):
    @catch_KeyboardInterrupt(self)
    def _callback(uc, access, addr, size, value, pack_data):
        # unpack what we packed for hook_add()
        user_data, callback = pack_data
        if user_data:
            callback(self, addr, size, value, user_data)
        else:
            # callback does not require user_data
            callback(self, addr, size, value)

    # pack user_data & callback for wrapper _callback
    self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, _callback, (user_data, callback), begin, end)

def hook_mem_read_invalid(self, callback, user_data=None, begin=1, end=0):
    @catch_KeyboardInterrupt(self)
    def _callback(uc, access, addr, size, value, pack_data):
        # unpack what we packed for hook_add()
        user_data, callback = pack_data
        if user_data:
            callback(self, addr, size, value, user_data)
        else:
            # callback does not require user_data
            callback(self, addr, size, value)

    # pack user_data & callback for wrapper _callback
    self.uc.hook_add(UC_HOOK_MEM_READ_INVALID, _callback, (user_data, callback), begin, end)

def hook_mem_write_invalid(self, callback, user_data=None, begin=1, end=0):
    @catch_KeyboardInterrupt(self)
    def _callback(uc, access, addr, size, value, pack_data):
        # unpack what we packed for hook_add()
        user_data, callback = pack_data
        if user_data:
            callback(self, addr, size, value, user_data)
        else:
            # callback does not require user_data
            callback(self, addr, size, value)

    # pack user_data & callback for wrapper _callback
    self.uc.hook_add(UC_HOOK_MEM_WRITE_INVALID, _callback, (user_data, callback), begin, end)

def hook_mem_fetch_invalid(self, callback, user_data=None, begin=1, end=0):
    @catch_KeyboardInterrupt(self)
    def _callback(uc, access, addr, size, value, pack_data):
        # unpack what we packed for hook_add()
        user_data, callback = pack_data
        if user_data:
            callback(self, addr, size, value, user_data)
        else:
            # callback does not require user_data
            callback(self, addr, size, value)

    # pack user_data & callback for wrapper _callback
    self.uc.hook_add(UC_HOOK_MEM_FETCH_INVALID, _callback, (user_data, callback), begin, end)

def hook_mem_invalid(self, callback, user_data=None, begin=1, end=0):
    @catch_KeyboardInterrupt(self)
    def _callback(uc, access, addr, size, value, pack_data):
        # unpack what we packed for hook_add()
        user_data, callback = pack_data
        if user_data:
            callback(self, addr, size, value, user_data)
        else:
            # callback does not require user_data
            callback(self, addr, size, value)

    # pack user_data & callback for wrapper _callback
    self.uc.hook_add(UC_HOOK_MEM_VALID, _callback, (user_data, callback), begin, end)

# a convenient API to set callback for a single address
def hook_address(self, callback, address, user_data=None):
    @catch_KeyboardInterrupt(self)
    def _callback(uc, _addr, _size, pack_data):
        # unpack what we packed for hook_add()
        user_data, callback = pack_data
        if user_data:
            callback(self, user_data)
        else:
            # callback does not require user_data
            callback(self)

    # pack user_data & callback for wrapper _callback
    self.uc.hook_add(UC_HOOK_CODE, _callback, (user_data, callback), address, address)

def hook_mem_read(self, callback, user_data=None, begin=1, end=0):
    @catch_KeyboardInterrupt(self)
    def _callback(uc, access, addr, size, value, pack_data):
        # unpack what we packed for hook_add()
        user_data, callback = pack_data
        if user_data:
            callback(self, addr, size, value, user_data)
        else:
            # callback does not require user_data
            callback(self, addr, size, value)

    # pack user_data & callback for wrapper _callback
    self.uc.hook_add(UC_HOOK_MEM_READ, _callback, (user_data, callback), begin, end)

def hook_mem_write(self, callback, user_data=None, begin=1, end=0):
    @catch_KeyboardInterrupt(self)
    def _callback(uc, access, addr, size, value, pack_data):
        # unpack what we packed for hook_add()
        user_data, callback = pack_data
        if user_data:
            callback(self, addr, size, value, user_data)
        else:
            # callback does not require user_data
            callback(self, addr, size, value)

    # pack user_data & callback for wrapper _callback
    self.uc.hook_add(UC_HOOK_MEM_WRITE, _callback, (user_data, callback), begin, end)

def hook_mem_fetch(self, callback, user_data=None, begin=1, end=0):
    @catch_KeyboardInterrupt(self)
    def _callback(uc, access, addr, size, value, pack_data):
        # unpack what we packed for hook_add()
        user_data, callback = pack_data
        if user_data:
            callback(self, addr, size, value, user_data)
        else:
            # callback does not require user_data
            callback(self, addr, size, value)

    # pack user_data & callback for wrapper _callback
    self.uc.hook_add(UC_HOOK_MEM_FETCH, _callback, (user_data, callback), begin, end)

def hook_insn(self, callback, arg1, user_data=None, begin=1, end=0):
    @catch_KeyboardInterrupt(self)
    def _callback_x86_syscall(uc, pack_data):
        # unpack what we packed for hook_add()
        user_data, callback = pack_data
        if user_data:
            callback(self, user_data)
        else:
            # callback does not require user_data
            callback(self)

    if arg1 == UC_X86_INS_SYSCALL:
        # pack user_data & callback for wrapper _callback
        self.uc.hook_add(UC_HOOK_INSN, _callback_x86_syscall, (user_data, callback), begin, end, arg1)
    else:
        self.uc.hook_add(UC_HOOK_INSN, callback, user_data, begin, end, arg1)
