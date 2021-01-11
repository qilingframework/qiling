#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys, logging
import logging, os, sys, types

from .const import *
from .filestruct import ql_file
from .mapper import QlFsMapper
from .utils import QlOsUtils

from qiling.const import QL_ARCH, QL_OS, QL_INTERCEPT, QL_OS_POSIX
from qiling.exception import QlErrorArch
from unicorn.x86_const import *

class QlOs(QlOsUtils):
    def __init__(self, ql):
        super(QlOs, self).__init__(ql)
        self.ql = ql
        self.fs_mapper = QlFsMapper(ql)
        self.child_processes = False
        self.thread_management = None
        self.profile = self.ql.profile
        self.current_path = self.profile.get("MISC", "current_path")
        self.exit_code = 0
        self.services = {}
        self.elf_mem_start = 0x0

        if not hasattr(sys.stdin, "fileno") or not hasattr(sys.stdout, "fileno") or not hasattr(sys.stderr, "fileno"):
            # IDAPython has some hack on standard io streams and thus they don't have corresponding fds.

            self.stdin  = sys.stdin.buffer  if hasattr(sys.stdin,  "buffer") else sys.stdin
            self.stdout = sys.stdout.buffer if hasattr(sys.stdout, "buffer") else sys.stdout
            self.stderr = sys.stderr.buffer if hasattr(sys.stderr, "buffer") else sys.stderr
            else:
            self.stdin  = ql_file('stdin',  sys.stdin.fileno())
            self.stdout = ql_file('stdout', sys.stdout.fileno())
            self.stderr = ql_file('stderr', sys.stderr.fileno())

        if self.ql.stdin != 0:
            self.stdin = self.ql.stdin

        if self.ql.stdout != 0:
            self.stdout = self.ql.stdout

        if self.ql.stderr != 0:
            self.stderr = self.ql.stderr

        # defult exit point
        self.exit_point = {
            16: 0xfffff,            # 20bit address lane
            32: 0x8fffffff,
            64: 0xffffffffffffffff
        }.get(self.ql.archbit, None)

        if self.ql.shellcoder:
            self.shellcoder_ram_size = int(self.profile.get("SHELLCODER", "ram_size"), 16)
            # this shellcode entrypoint does not work for windows
            # windows shellcode entry point will comes from pe loader
            self.entry_point = int(self.profile.get("SHELLCODER", "entry_point"), 16)

        # We can save every syscall called
        self.syscalls = {}
        self.syscalls_counter = 0
        self.appeared_strings = {}
        self.setup_output()


    def save(self):
        return {}

    def restore(self, saved_state):
        pass

    def set_syscall(self, target_syscall, intercept_function, intercept):
        if intercept == QL_INTERCEPT.ENTER:
            if isinstance(target_syscall, int):
                self.dict_posix_onEnter_syscall_by_num[target_syscall] = intercept_function
            else:
                syscall_name = "ql_syscall_" + str(target_syscall)
                self.dict_posix_onEnter_syscall[syscall_name] = intercept_function

        elif intercept == QL_INTERCEPT.EXIT:
            if self.ql.ostype in (QL_OS_POSIX):
                if isinstance(target_syscall, int):
                    self.dict_posix_onExit_syscall_by_num[target_syscall] = intercept_function
                else:
                    syscall_name = "ql_syscall_" + str(target_syscall)
                    self.dict_posix_onExit_syscall[syscall_name] = intercept_function                    

        else:
            if self.ql.ostype in (QL_OS_POSIX):
                if isinstance(target_syscall, int):
                    self.dict_posix_syscall_by_num[target_syscall] = intercept_function
                else:
                    syscall_name = "ql_syscall_" + str(target_syscall)
                    self.dict_posix_syscall[syscall_name] = intercept_function
            
            elif self.ql.ostype in (QL_OS.WINDOWS, QL_OS.UEFI):
                self.set_api(target_syscall, intercept_function)

    def set_api(self, api_name, intercept_function, intercept):
        if self.ql.ostype == QL_OS.UEFI:
            api_name = "hook_" + str(api_name)

        if intercept == QL_INTERCEPT.ENTER:
            if self.ql.ostype in (QL_OS.WINDOWS, QL_OS.UEFI):
                self.user_defined_api_onenter[api_name] = intercept_function
            else:
                self.add_function_hook(api_name, intercept_function, intercept) 

        elif intercept == QL_INTERCEPT.EXIT:
            if self.ql.ostype in (QL_OS.WINDOWS, QL_OS.UEFI):
                self.user_defined_api_onexit[api_name] = intercept_function  
            else:
                self.add_function_hook(api_name, intercept_function, intercept)           

        else:
            if self.ql.ostype in (QL_OS.WINDOWS, QL_OS.UEFI):
                self.user_defined_api[api_name] = intercept_function
            else:
                self.add_function_hook(api_name, intercept_function)  

    def find_containing_image(self, pc):
        for image in self.ql.loader.images:
            if image.base <= pc < image.end:
                return image

    def emu_error(self):
        logging.error("\n")

        for reg in self.ql.reg.register_mapping:
            if isinstance(reg, str):
                REG_NAME = reg
                REG_VAL = self.ql.reg.read(reg)
                logging.error("%s\t:\t 0x%x" % (REG_NAME, REG_VAL))

        logging.error("\n")
        logging.error("PC = 0x%x" % (self.ql.reg.arch_pc))
        containing_image = self.find_containing_image(self.ql.reg.arch_pc)
        if containing_image:
            offset = self.ql.reg.arch_pc - containing_image.base
            logging.error(" (%s+0x%x)" % (containing_image.path, offset))
        else:
            logging.info("\n")
        self.ql.mem.show_mapinfo()

        try:
            buf = self.ql.mem.read(self.ql.reg.arch_pc, 8)
            logging.error("%r" % ([hex(_) for _ in buf]))

            logging.info("\n")
            self.disassembler(self.ql, self.ql.reg.arch_pc, 64)
        except:
            logging.error("Error: PC(0x%x) Unreachable" % self.ql.reg.arch_pc)


    def _x86_set_args(self, args):
        for i in range(len(args)):
            # skip ret_addr
            self.ql.stack_write((i + 1) * 4, args[i])


    def _x8664_set_args(self, args):
        reg_list=None
        if self.ql.ostype == QL_OS.LINUX:
            reg_list = [UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_R10, UC_X86_REG_R8, UC_X86_REG_R9]
        elif self.ql.ostype == QL_OS.WINDOWS:
            reg_list = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]
        if reg_list!=None:
            for i in range(len(args)):
                self.ql.uc.reg_write(reg_list[i], args[i])


    def set_function_args(self, args):
        if self.ql.archtype == QL_ARCH.X86:   # 32bit
            self._x86_set_args(args)
        else:   # 64bit
            self._x8664_set_args(args)


    def _x86_get_params_by_index(self, index):
        # index starts from 0
        # skip ret_addr
        return self.ql.stack_read((index + 1) * 4)


    def _x8664_get_params_by_index(self, index):
        reg_list = ["rcx", "rdx", "r8", "r9"]
        if index < 4:
            return self.ql.reg.read(reg_list[index])

        index -= 4
        # skip ret_addr
        return self.ql.stack_read((index + 5) * 8)


    def get_param_by_index(self, index):
        if self.ql.archtype == QL_ARCH.X86:
            return self._x86_get_params_by_index(index)
        elif self.ql.archtype == QL_ARCH.X8664:
            return self._x8664_get_params_by_index(index)


    def _x86_get_args(self, number):
        arg_list = []
        for i in range(number):
            # skip ret_addr
            arg_list.append(self.ql.stack_read((i + 1) * 4))
        if number == 1:
            return arg_list[0]
        else:
            return arg_list


    def _x8664_get_args(self, number):
        reg_list = ["rcx", "rdx", "r8", "r9"]
        arg_list = []
        reg_num = number
        if reg_num > 4:
            reg_num = 4
        number -= reg_num
        for i in reg_list[:reg_num]:
            arg_list.append(self.ql.reg.read(i))
        for i in range(number):
            # skip ret_addr and 32 byte home space
            arg_list.append(self.ql.stack_read((i + 5) * 8))
        if reg_num == 1:
            return arg_list[0]
        else:
            return arg_list


    def set_function_params(self, in_params, out_params):
        index = 0
        for each in in_params:
            if in_params[each] == DWORD or in_params[each] == POINTER:
                out_params[each] = self.get_param_by_index(index)
            elif in_params[each] == ULONGLONG:
                if self.ql.archtype == QL_ARCH.X86:
                    low = self.get_param_by_index(index)
                    index += 1
                    high = self.get_param_by_index(index)
                    out_params[each] = high << 32 + low
                else:
                    out_params[each] = self.get_param_by_index(index)
            elif in_params[each] == STRING:
                ptr = self.get_param_by_index(index)
                if ptr == 0:
                    out_params[each] = 0
                else:
                    content = self.read_cstring(ptr)
                    out_params[each] = content
            elif in_params[each] == WSTRING:
                ptr = self.get_param_by_index(index)
                if ptr == 0:
                    out_params[each] = 0
                else:
                    content = self.read_wstring(ptr)
                    out_params[each] = content
            elif in_params[each] == GUID:
                ptr = self.get_param_by_index(index)
                if ptr == 0:
                    out_params[each] = 0
                else:
                    out_params[each] = str(self.read_guid(ptr))
            index += 1
        return index


    def get_function_param(self, number):
        if self.ql.archtype == QL_ARCH.X86:
            return self._x86_get_args(number)
        elif self.ql.archtype == QL_ARCH.X8664:
            return self._x8664_get_args(number)


    def set_return_value(self, ret):
        if self.ql.archtype == QL_ARCH.X86:
            self.ql.reg.eax = ret
        elif self.ql.archtype == QL_ARCH.X8664:
            self.ql.reg.rax = ret


    def get_return_value(self):
        if self.ql.archtype == QL_ARCH.X86:
            return self.ql.reg.eax
        elif self.ql.archtype == QL_ARCH.X8664:
            return self.ql.reg.rax

    #
    # stdcall cdecl fastcall cc
    #

    def __x86_cc(self, param_num, params, func, args, kwargs, passthru=False):
        # read params values
        if params is not None:
            param_num = self.set_function_params(params, args[2])

        # if set, fire up the on-enter hook
        if callable(self.winapi_func_onenter):
            address, params = self.winapi_func_onenter(*args, **kwargs)

            # override original args set
            args = (self.ql, address, params)

        # call function
        result = func(*args, **kwargs)

        # if set, fire up the on-exit hook
        if callable(self.winapi_func_onexit):
            self.winapi_func_onexit(*args, **kwargs)

        # set return value
        if result is not None:
            self.set_return_value(result)

        # print
        self.print_function(args[1], func.__name__, args[2], result, passthru)

        return result, param_num

    def clear_syscalls(self):
        self.syscalls = {}
        self.syscalls_counter = 0
        self.appeared_strings = {}

    def _call_api(self, name, params, result, address, return_address):
        params_with_values = {}

        if name.startswith("hook_"):
            name = name[5:]

            # printfs are shit
            if params is not None:
                self.set_function_params(params, params_with_values)

        self.syscalls.setdefault(name, []).append({
            "params": params_with_values,
            "result": result,
            "address": address,
            "return_address": return_address,
            "position": self.syscalls_counter
        })

        self.syscalls_counter += 1

    def x86_stdcall(self, param_num, params, func, args, kwargs, passthru=False):
        # if we check ret_addr before the call, we can't modify the ret_addr from inside the hook
        result, param_num = self.__x86_cc(param_num, params, func, args, kwargs, passthru)

        # get ret addr
        ret_addr = self.ql.stack_read(0)

        # append syscall to list
        self._call_api(func.__name__, params, result, self.ql.reg.arch_pc, ret_addr)

        if not passthru and self.PE_RUN:
            # update stack pointer
            self.ql.reg.arch_sp = self.ql.reg.arch_sp + ((param_num + 1) * 4)

            self.ql.reg.arch_pc = ret_addr

        return result

    def x86_cdecl(self, param_num, params, func, args, kwargs, passthru=False):
        result, _ = self.__x86_cc(param_num, params, func, args, kwargs)
        old_pc = self.ql.reg.arch_pc

        # append syscall to list
        self._call_api(func.__name__, params, result, old_pc, self.ql.stack_read(0))

        if not passthru and self.PE_RUN:
            self.ql.reg.arch_pc = self.ql.stack_pop()

        return result

    def x8664_fastcall(self, param_num, params, func, args, kwargs, passthru=False):
        result, _ = self.__x86_cc(param_num, params, func, args, kwargs)
        old_pc = self.ql.reg.arch_pc

        # append syscall to list
        self._call_api(func.__name__, params, result, old_pc, self.ql.stack_read(0))

        if not passthru and self.PE_RUN:
           self.ql.reg.arch_pc = self.ql.stack_pop()

        return result
