#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from inspect import signature, Parameter
from typing import TextIO, Union, Callable

from unicorn.arm64_const import UC_ARM64_REG_X8, UC_ARM64_REG_X16
from unicorn.arm_const import UC_ARM_REG_R7
from unicorn.mips_const import UC_MIPS_REG_V0
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_RAX

from qiling import Qiling
from qiling.cc import QlCC, intel, arm, mips
from qiling.const import QL_ARCH, QL_OS, QL_INTERCEPT
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
        super().__init__(ql)

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

        # TODO: use abstract to access __syscall_cc and __syscall_id_reg by defining a system call class
        self.__syscall_cc: QlCC = {
            QL_ARCH.ARM64: aarch64,
            QL_ARCH.ARM  : aarch32,
            QL_ARCH.MIPS : mipso32,
            QL_ARCH.X86  : intel32,
            QL_ARCH.X8664: intel64
        }[self.ql.archtype](ql)

        self._fd = QlFileDes([0] * NR_OPEN)

        # the QlOs constructor cannot assign the standard streams using their designated properties since
        # it runs before the _fd array is declared. instead, it assigns them to the private members and here
        # we force _fd to update manually.
        self.stdin  = self._stdin
        self.stdout = self._stdout
        self.stderr = self._stderr

        self._shms = {}

    @QlOs.stdin.setter
    def stdin(self, stream: TextIO) -> None:
        self._stdin = stream
        self._fd[0] = stream

    @QlOs.stdout.setter
    def stdout(self, stream: TextIO) -> None:
        self._stdout = stream
        self._fd[1] = stream

    @QlOs.stderr.setter
    def stderr(self, stream: TextIO) -> None:
        self._stderr = stream
        self._fd[2] = stream

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
        syscall_id = self.syscall
        syscall_name = map_syscall(self.ql, syscall_id)

        # get syscall on-enter hook (if any)
        hooks_dict = self.posix_syscall_hooks[QL_INTERCEPT.ENTER]
        onenter_hook = hooks_dict.get(syscall_name) or hooks_dict.get(syscall_id)

        # get syscall on-exit hook (if any)
        hooks_dict = self.posix_syscall_hooks[QL_INTERCEPT.EXIT]
        onexit_hook = hooks_dict.get(syscall_name) or hooks_dict.get(syscall_id)

        # get syscall replacement hook (if any)
        hooks_dict = self.posix_syscall_hooks[QL_INTERCEPT.CALL]
        syscall_hook = hooks_dict.get(syscall_name) or hooks_dict.get(syscall_id)

        if not syscall_hook:
            osname = ostype_convert_str(self.ql.ostype)
            os_syscalls = ql_get_module_function(f"qiling.os.{osname.lower()}", "syscall")
            posix_syscalls = ql_get_module_function(f"qiling.os.posix", "syscall")

            # look in os-specific and posix syscall hooks
            if syscall_name:
                syscall_hook = getattr(os_syscalls, syscall_name, None) or getattr(posix_syscalls, syscall_name, None)

        if syscall_hook:
            syscall_name = syscall_hook.__name__

            # extract the parameters list from hook signature
            param_names = tuple(signature(syscall_hook).parameters.values())

            # skip first arg (always 'ql') and filter out python special args (*args and **kwargs)
            param_names = [info.name for info in param_names[1:] if info.kind == Parameter.POSITIONAL_OR_KEYWORD]

            # read parameter values
            params = [self.__syscall_cc.getRawParam(i) for i in range(len(param_names))]

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
                self.ql.log.exception(f'Syscall ERROR: {syscall_name} DEBUG: {e}')
                raise e

            # print out log entry
            syscall_basename = syscall_name[len(SYSCALL_PREF):]
            args = []

            for name, value in zip(param_names, params):
                # cut the first part of the arg if it is of form fstatat64_fd
                if name.startswith(f'{syscall_basename}_'):
                    name = name.partition('_')[-1]

                args.append((name, f'{value:#x}'))

            sret = retval and QlOsPosix.getNameFromErrorCode(retval)
            self.utils.print_function(self.ql.reg.arch_pc, syscall_basename, args, sret, False)

            # record syscall statistics
            self.utils.syscalls.setdefault(syscall_name, []).append({
                "params": dict(zip(param_names, params)),
                "result": retval,
                "address": self.ql.reg.arch_pc,
                "return_address": None,
                "position": self.utils.syscalls_counter
            })

            self.utils.syscalls_counter += 1
        else:
            self.ql.log.warning(f'{self.ql.reg.arch_pc:#x}: syscall {syscall_name} number = {syscall_id:#x}({syscall_id:d}) not implemented')

            if self.ql.debug_stop:
                raise QlErrorSyscallNotFound(f'Syscall not found: {syscall_name}')

    def get_syscall(self) -> int:
        if self.ql.archtype == QL_ARCH.ARM:
            # When ARM-OABI
            # svc_imm = 0x900000 + syscall_nr
            # syscall_nr = svc_imm - 0x900000
            # Ref1: https://marcin.juszkiewicz.com.pl/download/tables/syscalls.html
            # Ref2: https://github.com/rootkiter/Reverse-bins/blob/master/syscall_header/armv4l_unistd.h
            # Ref3: https://github.com/unicorn-engine/unicorn/issues/1137
            code_val = self.ql.mem.read_ptr(self.ql.reg.arch_pc-4, 4)
            svc_imm  = code_val & 0x00ffffff
            if (svc_imm >= 0x900000):
                    return svc_imm - 0x900000
        return self.ql.reg.read(self.__syscall_id_reg)

    def set_syscall_return(self, retval: int):
        self.__syscall_cc.setReturnValue(retval)

    @property
    def fd(self):
        return self._fd
