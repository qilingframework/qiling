#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys, logging
from typing import Callable, Sequence, Mapping, MutableMapping, Any

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

        # choose a calling convention according to arch and os
        if self.ql.archtype in (QL_ARCH.X86, QL_ARCH.A8086):
            cc = 'cdecl'
        elif self.ql.archtype == QL_ARCH.X8664:
            cc = {
                QL_OS.LINUX:   'amd64',
                QL_OS.WINDOWS: 'ms',
                QL_OS.UEFI:    'ms'
            }.get(self.ql.ostype, '')
        else:
            # do not pick a cc; let class overrides define the necessary handlers
            cc = ''

        # registers used to pass arguments; a None stands for a stack argument
        self.__cc_args = {
            'amd64': (UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_R10, UC_X86_REG_R8, UC_X86_REG_R9, None, None),
            'cdecl': (None, ) * 8,
            'ms':    (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9, None, None, None, None)
        }.get(cc, [])

        # shadow stack size in terms of stack items
        self.__shadow = 4 if cc == 'ms' else 0

        # arch native address size in bytes
        self.__asize = self.ql.archbit // 8

        # register used to pass the return value to the caller
        self.__cc_reg_ret = {
            QL_ARCH.A8086: UC_X86_REG_AX,
            QL_ARCH.X86:   UC_X86_REG_EAX,
            QL_ARCH.X8664: UC_X86_REG_RAX
        }.get(self.ql.archtype, UC_X86_REG_INVALID)

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

    def set_function_args(self, args: Sequence[int]) -> None:
        """Set function call arguments.
        """

        for i, (reg, arg) in enumerate(zip(self.__cc_args, args)):
            # should arg be written to a reg or the stack?
            if reg is None:
                # get matching stack item
                si = i - self.__cc_args.index(None)

                # skip return address and shadow space
                self.ql.stack_write((1 + self.__shadow + si) * self.__asize, arg)
            else:
                self.ql.uc.reg_write(reg, arg)

    def get_param_by_index(self, index: int) -> int:
        """Get an argument value by its index.
        """

        max_args = len(self.__cc_args)
        assert index < max_args, f'currently supporting up to {max_args} args'

        reg = self.__cc_args[index]

        # should arg be read from a reg or the stack?
        if reg is None:
            # get matching stack item
            si = index - self.__cc_args.index(None)

            # skip return address and shadow space
            return self.ql.stack_read((1 + self.__shadow + si) * self.__asize)
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

        def __handle_POINTER(idx: int):
            return self.get_param_by_index(idx), 1

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
            DWORD    : __handle_POINTER,
            ULONGLONG: __handle_POINTER if self.ql.archbit == 64 else __handle_ULONGLONG_32,
            POINTER  : __handle_POINTER,
            STRING   : __handle_STRING,
            WSTRING  : __handle_WSTRING,
            GUID     : __handle_GUID
        }

        i = 0
        for pname, ptype in in_params.items():
            out_params[pname], consumed = param_handlers[ptype](i)
            i += consumed

        return i

    def set_return_value(self, ret: int):
        self.ql.uc.reg_write(self.__cc_reg_ret, ret)

    def get_return_value(self) -> int:
        return self.ql.uc.reg_read(self.__cc_reg_ret)

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
