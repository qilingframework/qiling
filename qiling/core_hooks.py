#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

##############################################
# These are part of the core.py Qiling class #
# handling hooks                             #
##############################################

from unicorn import *
from unicorn.x86_const import *
from .utils import catch_KeyboardInterrupt
from .const import QL_POSIX, QL_OS

class QLCoreHooks:
    def __init__(self):
        self.uc = None

    ########################
    # Callback definitions #
    ########################
    def _callback_type3(self, uc, intno, pack_data):
        ql, user_data, callback = pack_data     # unpack what we packed for hook_add()
        if user_data:
            return callback(ql, intno, user_data)
        return callback(ql, intno)              # callback does not require user_data

    def _callback_type4(self, uc, addr, size, pack_data):
        ql, user_data, callback = pack_data
        if user_data:
            return callback(ql, addr, size, user_data)
        return callback(ql, addr, size)

    def _callback_type4a(self, uc, _addr, _size, pack_data):
        ql, user_data, callback = pack_data
        if user_data:
            return callback(ql, user_data)
        return callback(ql)

    def _callback_type6(self, uc, access, addr, size, value, pack_data):
        ql, user_data, callback = pack_data
        if user_data:
            return callback(ql, addr, size, value, user_data)
        return callback(ql, addr, size, value)

    def _callback_x86_syscall(self, uc, pack_data):
        ql, user_data, callback = pack_data
        if user_data:
            return callback(ql, user_data)
        return callback(ql)

    ###############
    # Class Hooks #
    ###############

    def ql_hook(self, hook_type, callback_type, callback, user_data=None, begin=1, end=0, *args):
        _callback = (catch_KeyboardInterrupt(self))(callback_type)
        # pack user_data & callback for wrapper _callback
        self.uc.hook_add(hook_type, _callback, (self, user_data, callback), begin, end, *args)

    def hook_code(self, callback, user_data=None, begin=1, end=0):
        self.ql_hook(UC_HOOK_CODE, self._callback_type4, callback, user_data, begin, end)

    def hook_intr(self, callback, user_data=None, begin=1, end=0):
        self.ql_hook(UC_HOOK_INTR, self._callback_type3, callback, user_data, begin, end)

    def hook_block(self, callback, user_data=None, begin=1, end=0):
        self.ql_hook(UC_HOOK_BLOCK, self._callback_type4, callback, user_data, begin, end)

    def hook_mem_unmapped(self, callback, user_data=None, begin=1, end=0):
        self.ql_hook(UC_HOOK_MEM_UNMAPPED, self._callback_type6, callback, user_data, begin, end)

    def hook_mem_read_invalid(self, callback, user_data=None, begin=1, end=0):
        self.ql_hook(UC_HOOK_MEM_READ_INVALID, self._callback_type6, callback, user_data, begin, end)

    def hook_mem_write_invalid(self, callback, user_data=None, begin=1, end=0):
        self.ql_hook(UC_HOOK_MEM_WRITE_INVALID, self._callback_type6, callback, user_data, begin, end)

    def hook_mem_fetch_invalid(self, callback, user_data=None, begin=1, end=0):
        self.ql_hook(UC_HOOK_MEM_FETCH_INVALID, self._callback_type6, callback, user_data, begin, end)

    def hook_mem_invalid(self, callback, user_data=None, begin=1, end=0):
        self.ql_hook(UC_HOOK_MEM_VALID, self._callback_type6, callback, user_data, begin, end)

    # a convenient API to set callback for a single address
    def hook_address(self, callback, address, user_data=None):
        self.ql_hook(UC_HOOK_CODE, self._callback_type4a, callback, user_data, address, address)

    def hook_mem_read(self, callback, user_data=None, begin=1, end=0):
        self.ql_hook(UC_HOOK_MEM_READ, self._callback_type6, callback, user_data, begin, end)

    def hook_mem_write(self, callback, user_data=None, begin=1, end=0):
        self.ql_hook(UC_HOOK_MEM_WRITE, self._callback_type6, callback, user_data, begin, end)

    def hook_mem_fetch(self, callback, user_data=None, begin=1, end=0):
        self.ql_hook(UC_HOOK_MEM_FETCH, self._callback_type6, callback, user_data, begin, end)

    def hook_insn(self, callback, arg1, user_data=None, begin=1, end=0):
        if arg1 == UC_X86_INS_SYSCALL:
            # pack user_data & callback for wrapper _callback
            self.ql_hook(UC_HOOK_INSN, self._callback_x86_syscall, callback, user_data, begin, end, arg1)
        else:
            #TODO: Need to write test code to reach this code path and trigger
            #TODO: need to convert this to ql_hook style code
            self.uc.hook_add(UC_HOOK_INSN, callback, user_data, begin, end, arg1)
    
    # replace linux or windows syscall/api with custom api/syscall
    # if replace function name is needed, first syscall must be available
    # - ql.set_syscall(0x04, my_syscall_write)
    # - ql.set_syscall("write", my_syscall_write)
    def set_syscall(self, syscall_cur, syscall_new):
        if self.ostype in (QL_POSIX):
            if isinstance(syscall_cur, int):
                self.os.dict_posix_syscall_by_num[syscall_cur] = syscall_new
            else:
                syscall_name = "ql_syscall_" + str(syscall_cur)
                self.os.dict_posix_syscall[syscall_name] = syscall_new
        elif self.ostype == QL_OS.WINDOWS:
            self.set_api(syscall_cur, syscall_new)

    # replace Windows API with custom syscall
    def set_api(self, syscall_cur, syscall_new):
        if self.ostype == QL_OS.WINDOWS:
            self.os.user_defined_api[syscall_cur] = syscall_new
        elif self.ostype in (QL_POSIX):
            self.set_syscall(syscall_cur, syscall_new)
