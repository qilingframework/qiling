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
from qiling.cc import QlCC, intel, arm, mips
from qiling.const import QL_ARCH, QL_OS, QL_INTERCEPT, QL_CALL_BLOCK, QL_VERBOSE
from qiling.exception import QlErrorSyscallNotFound
from qiling.os.os import QlOs
from qiling.os.posix.const import errors, NR_OPEN
from qiling.utils import QlFileDes, ostype_convert_str, ql_get_module_function, ql_syscall_mapping_function

from qiling.os.posix.syscall import *
from qiling.os.linux.syscall import *
from qiling.os.macos.syscall import *
from qiling.os.freebsd.syscall import *
from qiling.os.qnx.syscall import *

SYSCALL_PREF: str = f'ql_syscall_'

class intel32(intel.QlIntel32):
    _argregs = (UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP)

class intel64(intel.QlIntel64):
    _argregs = (UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_R10, UC_X86_REG_R8, UC_X86_REG_R9)

class aarch32(arm.aarch32):
    _argregs = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5)

class aarch64(arm.aarch64):
    pass

class mipso32(mips.mipso32):
    # TODO: should it be part of the standard mipso32 cc?
    def setReturnValue(self, value: int):
        if -1134 < value < 0:
            a3return = 1
            value = -value
        else:
            a3return = 0

        self.ql.reg.v0 = value
        self.ql.reg.a3 = a3return

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
        if (self.ql.archtype == QL_ARCH.ARM) and (self.ql.ostype == QL_OS.QNX):
            self.__syscall_id_reg = UC_ARM_REG_R12

        self.__syscall_cc: QlCC = {
            QL_ARCH.ARM64: aarch64,
            QL_ARCH.ARM  : aarch32,
            QL_ARCH.MIPS : mipso32,
            QL_ARCH.X86  : intel32,
            QL_ARCH.X8664: intel64
        }[self.ql.archtype](ql)

        self._fd = QlFileDes([0] * NR_OPEN)
        self._fd[0] = self.stdin
        self._fd[1] = self.stdout
        self._fd[2] = self.stderr

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
        if type(ret) is not int:
            return '?'

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

        if syscall_hook:
            params = [self.__syscall_cc.getRawParam(i) for i in range(6)]

            try:
        		# if set, fire up the on-enter hook and let it override original args set
                if onenter_hook:
                    overrides = onenter_hook(self.ql, *params)

                    if overrides is not None:
                        _, params = overrides

        		# perform syscall
                retval = syscall_hook(self.ql, *params)

                # if set, fire up the on-exit hook and let it override the return value
                if onexit_hook:
                    override = onexit_hook(self.ql, *params, retval)

                    if override is not None:
                        retval = override

                # set return value
                if retval is not None:
                    self.__syscall_cc.setReturnValue(retval)

            except KeyboardInterrupt:
                raise

            except Exception as e:
                self.ql.log.exception("")
                self.ql.log.info(f'Syscall ERROR: {syscall_name} DEBUG: {e}')
                raise e

            # print out log entry
            syscall_basename = syscall_hook.__name__[len(SYSCALL_PREF):]
            args = []

            # ignore first arg, which is 'ql'
            arg_names = tuple(signature(syscall_hook).parameters.values())[1:]

            for name, value in zip(arg_names, params):
                name = str(name)

                # ignore python special args
                if name in ('*args', '**kw', '**kwargs'):
                    continue

                # cut the first part of the arg if it is of form fstatat64_fd
                if name.startswith(f'{syscall_basename}_'):
                    name = name.partition('_')[-1]

                args.append((name, f'{value:#x}'))

            sret = retval and QlOsPosix.getNameFromErrorCode(retval)
            self.utils.print_function(self.ql.reg.arch_pc, syscall_basename, args, sret, False)

            # record syscall statistics
            self.utils.syscalls.setdefault(syscall_name, []).append({
                "params": dict(zip((f'param{i}' for i in range(6)), params)),
                "result": retval,
                "address": self.ql.reg.arch_pc,
                "return_address": None,
                "position": self.utils.syscalls_counter
            })

            self.utils.syscalls_counter += 1
        else:
            self.ql.log.warning(f'{self.ql.reg.arch_pc:#x}: syscall {syscall_name} number = {syscall:#x}({syscall:d}) not implemented')

            if self.ql.debug_stop:
                raise QlErrorSyscallNotFound("Syscall Not Found")

    def get_syscall(self) -> int:
        return self.ql.reg.read(self.__syscall_id_reg)

    @property
    def fd(self):
        return self._fd