#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import os, sys, types

from .utils import QlOsUtils
from .const import *
from .filestruct import ql_file
from .mapper import QlFsMapper

from qiling.const import *

from unicorn.x86_const import *

class QlOs(QlOsUtils):
    def __init__(self, ql):
        super(QlOs, self).__init__(ql)
        self.ql = ql
        self.ql.uc = self.ql.arch.init_uc
        self.fs_mapper = QlFsMapper(ql)
        self.child_processes = False
        self.thread_management = None
        self.profile = self.ql.profile
        self.current_path = self.profile.get("MISC", "current_path")
        self.exit_code = 0
        self.services = {}
        self.elf_mem_start = 0x0

        if "fileno" not in dir(sys.stdin) or "fileno" not in dir(sys.stdout) or "fileno" not in dir(sys.stderr):
            # IDAPython has some hack on standard io streams and thus they don't have corresponding fds.
            if "buffer" in dir(sys.stdin):
                self.stdin = sys.stdin.buffer
            else:
                self.stdin = sys.stdin
            if "buffer" in dir(sys.stdout):
                self.stdout = sys.stdout.buffer
            else:
                self.stdout = sys.stdout
            if "buffer" in dir(sys.stderr):
                self.stderr = sys.stderr.buffer
            else:
                self.stderr = sys.stderr
        else:
            self.stdin = ql_file('stdin', sys.stdin.fileno())
            self.stdout = ql_file('stdout', sys.stdout.fileno())
            self.stderr = ql_file('stderr', sys.stderr.fileno())

        if self.ql.stdin != 0:
            self.stdin = self.ql.stdin

        if self.ql.stdout != 0:
            self.stdout = self.ql.stdout

        if self.ql.stderr != 0:
            self.stderr = self.ql.stderr

        if self.ql.archbit == 32:
            EMU_END = 0x8fffffff
        elif self.ql.archbit == 64:
            EMU_END = 0xffffffffffffffff
        
        elif self.ql.archbit == 16:
            # 20bit address lane
            EMU_END = 0xfffff   
        
        # defult exit point
        self.exit_point = EMU_END

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


    def find_containing_image(self, pc):
        for image in self.ql.loader.images:
            if image.base <= pc < image.end:
                return image

    def emu_error(self):
        self.ql.nprint("\n")

        for reg in self.ql.reg.register_mapping:
            if isinstance(reg, str):
                REG_NAME = reg
                REG_VAL = self.ql.reg.read(reg)
                self.ql.nprint("[-] %s\t:\t 0x%x" % (REG_NAME, REG_VAL))

        self.ql.nprint("\n")
        self.ql.nprint("[+] PC = 0x%x" % (self.ql.reg.arch_pc), end="")
        containing_image = self.find_containing_image(self.ql.reg.arch_pc)
        if containing_image:
            offset = self.ql.reg.arch_pc - containing_image.base
            self.ql.nprint(" (%s+0x%x)" % (containing_image.path, offset))
        else:
            self.ql.nprint("\n")
        self.ql.mem.show_mapinfo()

        try:
            buf = self.ql.mem.read(self.ql.reg.arch_pc, 8)
            self.ql.nprint("[+] %r" % ([hex(_) for _ in buf]))

            self.ql.nprint("\n")
            self.disassembler(self.ql, self.ql.reg.arch_pc, 64)
        except:
            self.ql.nprint("[!] Error: PC(0x%x) Unreachable" % self.ql.reg.arch_pc)


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
        # read params
        if params is not None:
            param_num = self.set_function_params(params, args[2])

        if isinstance(self.winapi_func_onenter, types.FunctionType):
            address, params = self.winapi_func_onenter(*args, **kwargs)
            args = (self.ql, address, params)
            onEnter = True
        else:
            onEnter = False

        # call function
        result = func(*args, **kwargs)

        if isinstance(self.winapi_func_onexit, types.FunctionType):
            self.winapi_func_onexit(*args, **kwargs)

        # set return value
        if result is not None:
            self.set_return_value(result)
        # print
        self.print_function(args[1], func.__name__, args[2], result, passthru)

        return result, param_num


    def _call_api(self, name, params, result, address, return_address):
        params_with_values = {}
        if name.startswith("hook_"):
            name = name.split("hook_", 1)[1]
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

        self.ql.os.syscalls_counter += 1


    def x86_stdcall(self, param_num, params, func, args, kwargs, passthru=False):
        # if we check ret_addr before the call, we can't modify the ret_addr from inside the hook
        result, param_num = self.__x86_cc(param_num, params, func, args, kwargs)

        # get ret addr
        ret_addr = self.ql.stack_read(0)

        # append syscall to list
        self._call_api(func.__name__, params, result, self.ql.reg.arch_pc, ret_addr)

        # update stack pointer
        self.ql.reg.arch_sp = self.ql.reg.arch_sp + ((param_num + 1) * 4)

        if not passthru and self.PE_RUN:
            self.ql.reg.arch_pc = ret_addr

        return result


    def x86_cdecl(self, param_num, params, func, args, kwargs, passthru=False):
        result, param_num = self.__x86_cc(param_num, params, func, args, kwargs)
        old_pc = self.ql.reg.arch_pc
        # append syscall to list
        self._call_api(func.__name__, params, result, old_pc, self.ql.stack_read(0))

        if not passthru and self.PE_RUN:
            self.ql.reg.arch_pc = self.ql.stack_pop()

        return result


    def x8664_fastcall(self, param_num, params, func, args, kwargs, passthru=False):
        result, param_num = self.__x86_cc(param_num, params, func, args, kwargs)

        old_pc = self.ql.reg.arch_pc
        # append syscall to list
        self._call_api(func.__name__, params, result, old_pc, self.ql.stack_read(0))

        if not passthru and self.PE_RUN:
           self.ql.reg.arch_pc = self.ql.stack_pop()

        return result
