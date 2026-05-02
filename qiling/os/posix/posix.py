#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from inspect import signature, Parameter
from typing import Dict, TextIO, Union, Callable, IO, List, Optional

from qiling import Qiling
from qiling.const import QL_ARCH, QL_INTERCEPT
from qiling.exception import QlErrorSyscallNotFound
from qiling.os.os import QlOs
from qiling.os.posix.const import NR_OPEN, NSIG, errors
from qiling.os.posix.msq import QlMsq
from qiling.os.posix.shm import QlShm
from qiling.os.posix.syscall.abi import QlSyscallABI, arm, intel, mips, ppc, riscv
from qiling.utils import ql_get_module, ql_get_module_function

SYSCALL_PREF: str = f'ql_syscall_'


class QlFileDes:
    def __init__(self):
        self.__fds: List[Optional[IO]] = [None] * NR_OPEN

    def __len__(self):
        return len(self.__fds)

    def __getitem__(self, idx: int):
        return self.__fds[idx]

    def __setitem__(self, idx: int, val: Optional[IO]):
        self.__fds[idx] = val

    def __iter__(self):
        return iter(self.__fds)

    def __repr__(self):
        return repr(self.__fds)

    def save(self):
        return self.__fds

    def restore(self, fds):
        self.__fds = fds


class QlOsPosix(QlOs):

    def __init__(self, ql: Qiling):
        super().__init__(ql)

        conf = self.profile['KERNEL']
        self.uid = self.euid = conf.getint('uid')
        self.gid = self.egid = conf.getint('gid')
        self.pid = conf.getint('pid')

        conf = self.profile['NETWORK']
        self.ipv6 = conf.getboolean('ipv6')
        self.bindtolocalhost = conf.getboolean('bindtolocalhost')
        self.ifrname_ovr = conf.get('ifrname_override')

        self.posix_syscall_hooks = {
            QL_INTERCEPT.CALL:  {},
            QL_INTERCEPT.ENTER: {},
            QL_INTERCEPT.EXIT:  {}
        }

        self.syscall_abi: QlSyscallABI = {
            QL_ARCH.ARM64:   arm.QlAArch64,
            QL_ARCH.ARM:     arm.QlAArch32,
            QL_ARCH.MIPS:    mips.QlMipsO32,
            QL_ARCH.X86:     intel.QlIntel32,
            QL_ARCH.X8664:   intel.QlIntel64,
            QL_ARCH.RISCV:   riscv.QlRiscV32,
            QL_ARCH.RISCV64: riscv.QlRiscV64,
            QL_ARCH.PPC:     ppc.QlPPC
        }[self.ql.arch.type](self.ql.arch)

        # select syscall mapping function based on emulated OS and architecture
        self.syscall_mapper = self.__get_syscall_mapper(self.ql.arch.type)

        self._fd = QlFileDes()

        # the QlOs constructor cannot assign the standard streams using their designated properties since
        # it runs before the _fd array is declared. instead, it assigns them to the private members and here
        # we force _fd to update manually.
        self.stdin  = self._stdin
        self.stdout = self._stdout
        self.stderr = self._stderr

        self._shm = QlShm()
        self._msq = QlMsq()
        self._sig = [None] * NSIG

        # a bitmap representing the blocked signals. a set bit at index i means signal i is blocked.
        # note that SIGKILL and SIGSTOP cannot be blocked.
        self.blocked_signals = 0

    def __get_syscall_mapper(self, archtype: QL_ARCH):
        qlos_path = f'.os.{self.type.name.lower()}.map_syscall'
        qlos_func = 'get_syscall_mapper'

        func = ql_get_module_function(qlos_path, qlos_func)

        return func(archtype)

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

    @QlOs.root.getter
    def root(self) -> bool:
        return (self.euid == 0) and (self.egid == 0)

    @QlOs.root.setter
    def root(self, enabled: bool) -> None:
        self.euid = 0 if enabled else self.uid
        self.egid = 0 if enabled else self.gid

    def set_syscall(self, target: Union[int, str], handler: Callable, intercept: QL_INTERCEPT = QL_INTERCEPT.CALL):
        """Either hook or replace a system call with a custom one.

        Args:
            target: either syscall name or number. a name may be used only if target syscall is implemented
            handler: function to call
            intercept:
                `QL_INTERCEPT.CALL` : run handler instead of the existing target implementation
                `QL_INTERCEPT.ENTER`: run handler before the target syscall is called
                `QL_INTERCEPT.EXIT` : run handler after the target syscall is called
        """

        if type(target) is str:
            target = f'{SYSCALL_PREF}{target}'

        self.posix_syscall_hooks[intercept][target] = handler

    def set_api(self, target: str, handler: Callable, intercept: QL_INTERCEPT = QL_INTERCEPT.CALL):
        if self.ql.loader.is_driver:
            super().set_api(target, handler, intercept)
        else:
            self.function_hook.add_function_hook(target, handler, intercept)

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
        syscall_id = self.syscall_abi.get_id()
        syscall_name = self.syscall_mapper(syscall_id)

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
            def __get_os_module(osname: str):
                return ql_get_module(f'.os.{osname.lower()}.syscall')

            os_syscalls = __get_os_module(self.type.name)
            posix_syscalls = __get_os_module('posix')

            # look in os-specific and posix syscall hooks
            syscall_hook = getattr(os_syscalls, syscall_name, None) or getattr(posix_syscalls, syscall_name, None)

        if syscall_hook:
            syscall_name = syscall_hook.__name__

            # extract the parameters list from hook signature
            param_names = tuple(signature(syscall_hook).parameters.values())

            # skip first arg (always 'ql') and filter out python special args (*args and **kwargs)
            param_names = [info.name for info in param_names[1:] if info.kind == Parameter.POSITIONAL_OR_KEYWORD]

            # read parameter values
            params = self.syscall_abi.get_params(len(param_names))

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
                    self.syscall_abi.set_return_value(retval)

            except KeyboardInterrupt:
                raise

            except Exception as e:
                self.ql.log.exception(f'Syscall ERROR: {syscall_name} DEBUG: {e}')
                raise e

            # print out log entry
            syscall_basename = syscall_name[len(SYSCALL_PREF) if syscall_name.startswith(SYSCALL_PREF) else 0:]

            args = []

            for name, value in zip(param_names, params):
                # cut the first part of the arg if it is of form fstatat64_fd
                if name.startswith(f'{syscall_basename}_'):
                    name = name.partition('_')[-1]

                args.append((name, f'{value:#x}'))

            sret = QlOsPosix.getNameFromErrorCode(retval)
            self.utils.print_function(self.ql.arch.regs.arch_pc, syscall_basename, args, sret, False)

            # record syscall statistics
            self.stats.log_api_call(self.ql.arch.regs.arch_pc, syscall_name, dict(zip(param_names, params)), retval, None)
        else:
            self.ql.log.warning(f'{self.ql.arch.regs.arch_pc:#x}: syscall {syscall_name} number = {syscall_id:#x}({syscall_id:d}) not implemented')

            if self.ql.debug_stop:
                raise QlErrorSyscallNotFound(f'Syscall not found: {syscall_name}')

    @property
    def fd(self):
        return self._fd

    @property
    def shm(self):
        return self._shm

    @property
    def msq(self):
        return self._msq

    @property
    def sig(self):
        return self._sig
