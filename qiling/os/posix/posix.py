#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from inspect import signature
from typing import Union, Callable

from unicorn.arm64_const import UC_ARM64_REG_X8, UC_ARM64_REG_X16
from unicorn.arm_const import UC_ARM_REG_R7
from unicorn.mips_const import UC_MIPS_REG_V0
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_RAX

from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_INTERCEPT, QL_CALL_BLOCK, QL_VERBOSE
from qiling.exception import QlErrorSyscallNotFound
from qiling.os.os import QlOs
from qiling.os.posix.const import errors
from qiling.utils import QlFileDes, ostype_convert_str, ql_get_module_function, ql_syscall_mapping_function

from qiling.os.posix.syscall import *
from qiling.os.linux.syscall import *
from qiling.os.macos.syscall import *
from qiling.os.freebsd.syscall import *

SYSCALL_PREF: str = f'ql_syscall_'

class QlOsPosix(QlOs):

    def __init__(self, ql: Qiling):
        super(QlOsPosix, self).__init__(ql)

        self.ql = ql
        self.sigaction_act = [0] * 256

        if self.ql.root:
            self.uid = 0
            self.gid = 0
        else:
            self.uid = self.profile.getint("KERNEL","uid")
            self.gid = self.profile.getint("KERNEL","gid")

        self.pid = self.profile.getint("KERNEL", "pid")
        self.ipv6 = self.profile.getboolean("NETWORK", "ipv6")
        self.bindtolocalhost = self.profile.getboolean("NETWORK", "bindtolocalhost")

        self.posix_syscall_hooks = {
            QL_INTERCEPT.CALL : {},
            QL_INTERCEPT.ENTER: {},
            QL_INTERCEPT.EXIT : {}
        }

        self.__syscall_id_reg = {
            QL_ARCH.ARM64: UC_ARM64_REG_X8,
            QL_ARCH.ARM  : UC_ARM_REG_R7,
            QL_ARCH.MIPS : UC_MIPS_REG_V0,
            QL_ARCH.X86  : UC_X86_REG_EAX,
            QL_ARCH.X8664: UC_X86_REG_RAX
        }[self.ql.archtype]

        # handle a special case
        if (self.ql.archtype == QL_ARCH.ARM64) and (self.ql.ostype == QL_OS.MACOS):
            self.__syscall_id_reg = UC_ARM64_REG_X16

        def __set_syscall_ret_arm(retval: int):
            self.ql.reg.r0 = retval

        def __set_syscall_ret_arm64(retval: int):
            self.ql.reg.x0 = retval

        def __set_syscall_ret_x86(retval: int):
            self.ql.reg.eax = retval

        def __set_syscall_ret_x8664(retval: int):
            self.ql.reg.rax = retval

        def __set_syscall_ret_mips(retval: int):
            if -1134 < retval < 0:
                a3return = 1
                retval = -retval
            else:
                a3return = 0

            self.ql.reg.v0 = retval
            self.ql.reg.a3 = a3return

            return retval

        self.__set_syscall_retval: Callable = {
            QL_ARCH.ARM64: __set_syscall_ret_arm64,
            QL_ARCH.ARM  : __set_syscall_ret_arm,
            QL_ARCH.MIPS : __set_syscall_ret_mips,
            QL_ARCH.X86  : __set_syscall_ret_x86,
            QL_ARCH.X8664: __set_syscall_ret_x8664
        }[self.ql.archtype]

        def __syscall_args_arm64():
            return (
                self.ql.reg.x0,
                self.ql.reg.x1,
                self.ql.reg.x2,
                self.ql.reg.x3,
                self.ql.reg.x4,
                self.ql.reg.x5
            )

        def __syscall_args_arm():
            return (
                self.ql.reg.r0,
                self.ql.reg.r1,
                self.ql.reg.r2,
                self.ql.reg.r3,
                self.ql.reg.r4,
                self.ql.reg.r5
            )

        def __syscall_args_mips():
            return (
                self.ql.reg.a0,
                self.ql.reg.a1,
                self.ql.reg.a2,
                self.ql.reg.a3,
                self.ql.reg.sp + 0x10,
                self.ql.reg.sp + 0x14
            )

        def __syscall_args_x86():
            return (
                self.ql.reg.ebx,
                self.ql.reg.ecx,
                self.ql.reg.edx,
                self.ql.reg.esi,
                self.ql.reg.edi,
                self.ql.reg.ebp
            )

        def __syscall_args_x8664():
            return (
                self.ql.reg.rdi,
                self.ql.reg.rsi,
                self.ql.reg.rdx,
                self.ql.reg.r10,
                self.ql.reg.r8,
                self.ql.reg.r9
            )

        self.__syscall_args: Callable = {
            QL_ARCH.ARM64: __syscall_args_arm64,
            QL_ARCH.ARM  : __syscall_args_arm,
            QL_ARCH.MIPS : __syscall_args_mips,
            QL_ARCH.X86  : __syscall_args_x86,
            QL_ARCH.X8664: __syscall_args_x8664
        }[self.ql.archtype]

        self.fd = QlFileDes([0] * 256)
        self.fd[0] = self.stdin
        self.fd[1] = self.stdout
        self.fd[2] = self.stderr

    # ql.syscall - get syscall for all posix series
    @property
    def syscall(self):
        return self.get_syscall()

    def set_syscall(self, target: Union[int, str], handler: Callable, intercept: QL_INTERCEPT):
        if type(target) is str:
            target = f'{SYSCALL_PREF}{target}'

        # BUG: workaround missing arg
        if intercept is None:
            intercept = QL_INTERCEPT.CALL

        self.posix_syscall_hooks[intercept][target] = handler

        # if intercept == QL_INTERCEPT.CALL:
        #     if self.ql.ostype in (QL_OS.WINDOWS, QL_OS.UEFI):
        #         self.set_api(target_syscall, intercept_function)

    @staticmethod
    def getNameFromErrorCode(ret: int) -> str:
        """Return the hex representation of a return value and if possible
        add the corresponding error name to it.

        Args:
            param ret: Return value of a syscall.

        Returns: The string representation of the error.
        """

        return f'{ret:#x}{f" ({errors[-ret]})" if -ret in errors else f""}'


    def load_syscall(self):
        # import syscall mapping function
        map_syscall = ql_syscall_mapping_function(self.ql.ostype)
        syscall = self.syscall
        syscall_name = map_syscall(self.ql, syscall)

        # get syscall on-enter hook (if any)
        hooks_dict = self.posix_syscall_hooks[QL_INTERCEPT.ENTER]
        onenter_hook = hooks_dict.get(syscall_name) or hooks_dict.get(syscall)

        # get syscall on-exit hook (if any)
        hooks_dict = self.posix_syscall_hooks[QL_INTERCEPT.EXIT]
        onexit_hook = hooks_dict.get(syscall_name) or hooks_dict.get(syscall)

        # get syscall replacement hook (if any)
        hooks_dict = self.posix_syscall_hooks[QL_INTERCEPT.CALL]
        syscall_hook = hooks_dict.get(syscall_name) or hooks_dict.get(syscall)

        if syscall_hook:
            syscall_name = syscall_hook.__name__
        else:
            _ostype_str = ostype_convert_str(self.ql.ostype)
            _posix_syscall = ql_get_module_function(f"qiling.os.posix", "syscall")
            _os_syscall = ql_get_module_function(f"qiling.os.{_ostype_str.lower()}", "syscall")

            if syscall_name in dir(_posix_syscall) or syscall_name in dir(_os_syscall):
                syscall_hook = eval(syscall_name)
                syscall_name = syscall_hook.__name__
            else:
                syscall_hook = None
                syscall_name = None

        if syscall_hook:
            args = self.get_syscall_args()

            self.utils.syscalls.setdefault(syscall_name, []).append({
                "params": {
                    "param0": args[0],
                    "param1": args[1],
                    "param2": args[2],
                    "param3": args[3],
                    "param4": args[4],
                    "param5": args[5]
                },
                "result": None,
                "address": self.ql.reg.arch_pc,
                "return_address": None,
                "position": self.utils.syscalls_counter
            })

            self.utils.syscalls_counter += 1

            try:
                ret = 0

                if onenter_hook is not None:
                    ret = onenter_hook(self.ql, *self.get_syscall_args())

                if type(ret) is not int or (ret & QL_CALL_BLOCK) == 0:
                    syscall_basename = syscall_hook.__name__[len(SYSCALL_PREF):]
                    args = []

                    # ignore first arg, which is 'ql'
                    arg_names = tuple(signature(syscall_hook).parameters.values())[1:]
                    arg_values = self.get_syscall_args()

                    for name, value in zip(arg_names, arg_values):
                        name = str(name)

                        # ignore python special args
                        if name in ('*args', '**kw', '**kwargs'):
                            continue

                        # cut the first part of the arg if it is of form fstatat64_fd
                        if name.startswith(f'{syscall_basename}_'):
                            name = name.partition('_')[-1]

                        args.append(f'{name} = {value:#x}')

                    faddr = f'{self.ql.reg.arch_pc:#0{self.ql.archbit // 4 + 2}x}: ' if self.ql.verbose >= QL_VERBOSE.DEBUG else ''
                    fargs = ', '.join(args)

                    log = f'{faddr}{syscall_basename}({fargs})'

                    if self.ql.verbose >= QL_VERBOSE.DEBUG:
                        self.ql.log.debug(log)
                    else:
                        self.ql.log.info(log)

                    ret = syscall_hook(self.ql, *arg_values)

                    if ret is not None and type(ret) is int:
                        # each name has a list of calls, we want the last one and we want to update the return value
                        self.utils.syscalls[syscall_name][-1]["result"] = ret
                        ret = self.set_syscall_return(ret)
                        self.ql.log.debug(f'{syscall_basename}() = {QlOsPosix.getNameFromErrorCode(ret)}')

                if onexit_hook is not None:
                    onexit_hook(self.ql, *self.get_syscall_args())

            except KeyboardInterrupt:
                raise
            except Exception as e:
                self.ql.log.exception("")
                self.ql.log.info(f'Syscall ERROR: {syscall_name} DEBUG: {e}')
                raise e
        else:
            self.ql.log.warning(f'{self.ql.reg.arch_pc:#x}: syscall number {syscall:#x} ({syscall:d}) not implemented')

            if self.ql.debug_stop:
                raise QlErrorSyscallNotFound("Syscall Not Found")

    def get_syscall(self) -> int:
        return self.ql.reg.read(self.__syscall_id_reg)

    def set_syscall_return(self, retval: int) -> int:
        return self.__set_syscall_retval(retval) or retval

    def get_syscall_args(self):
        return self.__syscall_args()
