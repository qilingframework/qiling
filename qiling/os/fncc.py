#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os

from typing import Callable, Sequence, Mapping, MutableMapping, Any
from functools import wraps

from qiling.os.const import *
from qiling.os.windows.utils import *
from qiling.const import *
from qiling.exception import *
from qiling.os.windows.structs import *

from .utils import *

class QlOsFncc:
    def __init__(self, ql):
        self.ql = ql

        # choose a calling convention according to arch and os
        if self.ql.archtype in (QL_ARCH.X86, QL_ARCH.A8086):
            cc = 'cdecl'
        elif self.ql.archtype == QL_ARCH.X8664:
            cc = {
                QL_OS.LINUX:   'amd64',
                QL_OS.MACOS:   'macosx64',
                QL_OS.WINDOWS: 'ms',
                QL_OS.UEFI:    'ms'
            }.get(self.ql.ostype, '')
        elif self.ql.archtype == QL_ARCH.MIPS:
            cc = {
                QL_OS.LINUX:   'mips_o32'
            }.get(self.ql.ostype, '')                        
        else:
            # do not pick a cc; let class overrides define the necessary handlers
            cc = ''

        # register used to pass the return value to the caller
        self.__cc_reg_ret = {
            QL_ARCH.A8086: UC_X86_REG_AX,
            QL_ARCH.X86:   UC_X86_REG_EAX,
            QL_ARCH.X8664: UC_X86_REG_RAX,
            QL_ARCH.MIPS: UC_MIPS_REG_2
        }.get(self.ql.archtype, UC_X86_REG_INVALID)

        # registers used to pass arguments; a None stands for a stack argument
        self._cc_args = {
            'amd64': (UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_R10, UC_X86_REG_R8, UC_X86_REG_R9) + (None, ) * 10,
            'macosx64': (UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9) + (None, ) * 10,
            'cdecl': (None, ) * 16,
            'ms':    (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9) + (None, ) * 12,
            'mips_o32':  (UC_MIPS_REG_4, UC_MIPS_REG_5, UC_MIPS_REG_6, UC_MIPS_REG_7) + (None, ) * 31
        }.get(cc, [])

        # shadow stack size in terms of stack items
        self._shadow = 4 if cc == 'ms' else 0

        # arch native address size in bytes
        self._asize = self.ql.archbit // 8

    def get_param_by_index(self, index: int) -> int:
        """Get an argument value by its index.
        """
        max_args = len(self._cc_args)
        assert index < max_args, f'currently supporting up to {max_args} args'

        reg = self._cc_args[index]

        # should arg be read from a reg or the stack?
        if reg is None:
            if self.ql.archtype == QL_ARCH.MIPS:
                return self.ql.stack.read(index * self._asize)

            # get matching stack item
            si = index - self._cc_args.index(None)

            # skip return address and shadow space
            return self.ql.stack_read((1 + self._shadow + si) * self._asize)
        else:
            return self.ql.uc.reg_read(reg)


    def get_function_param(self, nargs: int) -> list:
        """Get values of `nargs` first arguments.
        """

        params = [self.get_param_by_index(i) for i in range(nargs)]

        return params[0] if nargs == 1 else params

    def set_function_params(self, in_params: Mapping[str, int], out_params: MutableMapping[str, Any]) -> int:
        """Retrieve parameters values according to their assigned type.

        Args:
            in_params : a mapping of parameter names to their types
            out_params: a mapping of parameter names to their values
        Returns: number of consumed arguments; this is only relevant for the cdecl
        calling convention, where all the arguments are stored on the stack. in that
        case, the value reflects the number of items consumed from the stack
        """

        def __nullptr_or_deref(idx: int, deref: Callable[[int], Any]):
            ptr = self.get_param_by_index(idx)

            return deref(ptr) if ptr else 0

        def __handle_default(idx: int):
            return self.get_param_by_index(idx), 1

        def __handle_POINTER(idx: int):
            return __handle_default(idx)

        def __handle_ULONGLONG_32(idx: int):
            lo = self.get_param_by_index(idx)
            hi = self.get_param_by_index(idx + 1)

            return (hi << 32) | lo, 2

        def __handle_STRING(idx: int):
            return __nullptr_or_deref(idx, self.read_cstring), 1

        def __handle_WSTRING(idx: int):
            return __nullptr_or_deref(idx, self.read_wstring), 1

        def __handle_GUID(idx: int):
            return __nullptr_or_deref(idx, lambda p: str(self.read_guid(p))), 1

        param_handlers = {
            ULONGLONG: __handle_POINTER if self.ql.archbit == 64 else __handle_ULONGLONG_32,
            POINTER  : __handle_POINTER,
            STRING   : __handle_STRING,
            WSTRING  : __handle_WSTRING,
            GUID     : __handle_GUID
        }

        i = 0
        for pname, ptype in in_params.items():
            handler = param_handlers.get(ptype, __handle_default)
            out_params[pname], consumed = handler(i)
            i += consumed

        return i

    def set_return_value(self, ret: int):
        self.ql.uc.reg_write(self.__cc_reg_ret, ret)

    def get_return_value(self) -> int:
        return self.ql.uc.reg_read(self.__cc_reg_ret)

    #
    # stdcall cdecl fastcall cc
    #
    def __cc(self, param_num, params, func, args, kwargs, passthru=False):
        # read params values
        if params is not None:
            param_num = self.set_function_params(params, args[2])


        if self.ql.ostype in (QL_OS.WINDOWS, QL_OS.UEFI):
            # if set, fire up the on-enter hook
            if callable(self.winapi_func_onenter):
                address, params = self.winapi_func_onenter(*args, **kwargs)

                # override original args set
                args = (self.ql, address, params)

        # call function
        result = func(*args, **kwargs)

        if self.ql.ostype in (QL_OS.WINDOWS, QL_OS.UEFI):
            # if set, fire up the on-exit hook
            if callable(self.winapi_func_onexit):
                self.winapi_func_onexit(*args, **kwargs)

        # set return value
        if result is not None:
            self.set_return_value(result)

        # print
        self.print_function(args[1], func.__name__, args[2], result, passthru)

        return result, param_num

    def x86_stdcall(self, param_num, params, func, args, kwargs, passthru=False):
        # if we check ret_addr before the call, we can't modify the ret_addr from inside the hook
        result, param_num = self.__cc(param_num, params, func, args, kwargs, passthru)

        ret_addr = self.ql.stack_read(0)

        # append syscall to list
        if self.ql.ostype in (QL_OS.WINDOWS, QL_OS.UEFI):
            self._call_api(func.__name__, params, result, self.ql.reg.arch_pc, ret_addr)
            if not self.PE_RUN:
                return result
        
        if not passthru:
            # callee is responsible for cleaning up the stack; unwind the stack
            self.ql.reg.arch_sp = self.ql.reg.arch_sp + ((param_num + 1) * self._asize)
            self.ql.reg.arch_pc = ret_addr

        return result

    def x86_cdecl(self, param_num, params, func, args, kwargs, passthru=False):
        result, _ = self.__cc(param_num, params, func, args, kwargs)
        old_pc = self.ql.reg.arch_pc

        # append syscall to list
        if self.ql.ostype in (QL_OS.WINDOWS, QL_OS.UEFI):
            self._call_api(func.__name__, params, result, old_pc, self.ql.stack_read(0))
            if not self.PE_RUN:
                return result

        if not passthru:
            self.ql.reg.arch_pc = self.ql.stack_pop()

        return result

    def x8664_fastcall(self, param_num, params, func, args, kwargs, passthru=False):
        result, param_num = self.__cc(param_num, params, func, args, kwargs)
        old_pc = self.ql.reg.arch_pc

        # append syscall to list
        if self.ql.ostype in (QL_OS.WINDOWS, QL_OS.UEFI):
            self._call_api(func.__name__, params, result, old_pc, self.ql.stack_read(0))
            if not self.PE_RUN:
                return result

        if not passthru:
            self.ql.reg.arch_pc = self.ql.stack_pop()
        
        return result

    def mips_o32_call(self, param_num, params, func, args, kwargs):
        result, param_num  = self.__cc(param_num, params, func, args, kwargs)
        self.ql.reg.arch_pc = self.ql.reg.ra

        return result