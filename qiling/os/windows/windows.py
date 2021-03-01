#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn import UcError

from qiling.arch.x86 import GDTManager, ql_x86_register_cs, ql_x86_register_ds_ss_es, ql_x86_register_fs, ql_x86_register_gs, ql_x8664_set_gs
from qiling.exception import QlErrorSyscallError, QlErrorSyscallNotFound
from qiling.os.os import QlOs
from qiling.os.fncc import QlOsFncc

from .clipboard import Clipboard
from .fiber import FiberManager
from .registry import RegistryManager

from .dlls import *

class QlOsWindows(QlOs, QlOsFncc):
    def __init__(self, ql):
        QlOs.__init__(self, ql)
        QlOsFncc.__init__(self, ql)
        self.ql = ql
        self.PE_RUN = True
        self.last_error = 0
        # variables used inside hooks
        self.hooks_variables = {}
        self.syscall_count = {}
        self.argv = self.ql.argv
        self.env = self.ql.env
        self.pid = self.profile.getint("KERNEL","pid")
        self.ql.hook_mem_unmapped(ql_x86_windows_hook_mem_error)
        self.automatize_input = self.profile.getboolean("MISC","automatize_input")
        self.username = self.profile["USER"]["username"]
        self.windir = self.profile["PATH"]["systemdrive"] + self.profile["PATH"]["windir"]
        self.userprofile = self.profile["PATH"]["systemdrive"] + "Users\\" + self.profile["USER"]["username"] + "\\"
        self.load()


    def load(self):
        self.setupGDT()
        # hook win api
        self.ql.hook_code(self.hook_winapi)


    def setupGDT(self):
        # setup gdt
        if self.ql.archtype == QL_ARCH.X86:
            self.gdtm = GDTManager(self.ql)
            ql_x86_register_cs(self)
            ql_x86_register_ds_ss_es(self)
            ql_x86_register_fs(self)
            ql_x86_register_gs(self)
        elif self.ql.archtype == QL_ARCH.X8664:
            ql_x8664_set_gs(self.ql)


    def setupComponents(self):
        # handle manager
        self.handle_manager = HandleManager()
        # registry manger
        self.registry_manager = RegistryManager(self.ql)
        # clipboard
        self.clipboard = Clipboard(self.ql.os)
        # fibers
        self.fiber_manager = FiberManager(self.ql)
        # thread manager
        main_thread = QlWindowsThread(self.ql)
        self.thread_manager = QlWindowsThreadManagement(self.ql, main_thread)

        # more handle manager
        new_handle = Handle(obj=main_thread)
        self.handle_manager.append(new_handle)


    # hook WinAPI in PE EMU
    def hook_winapi(self, ql, address: int, size: int):
        if address in self.ql.loader.import_symbols:
            entry = self.ql.loader.import_symbols[address]
            winapi_name = entry['name']

            if winapi_name is None:
                winapi_name = Mapper[entry['dll']][entry['ordinal']]
            else:
                winapi_name = winapi_name.decode()

            winapi_func = self.user_defined_api[QL_INTERCEPT.CALL].get(winapi_name)

            if not winapi_func:
                winapi_func = globals().get(f'hook_{winapi_name}')

                self.syscall_count.setdefault(winapi_name, 0)
                self.syscall_count[winapi_name] += 1

            self.api_func_onenter = self.user_defined_api[QL_INTERCEPT.ENTER].get(winapi_name)
            self.api_func_onexit = self.user_defined_api[QL_INTERCEPT.EXIT].get(winapi_name)

            if winapi_func:
                try:
                    winapi_func(self.ql, address)
                except Exception as ex:
                    self.ql.log.exception(ex)
                    self.ql.log.info("%s Exception Found" % winapi_name)
                    self.emu_error()
                    raise QlErrorSyscallError("Windows API Implementation Error")
            else:
                self.ql.log.warning("%s is not implemented" % winapi_name)
                if self.ql.debug_stop:
                    raise QlErrorSyscallNotFound("Windows API Implementation Not Found")


    def post_report(self):
        self.ql.log.debug("Syscalls called")
        for key, values in self.utils.syscalls.items():
            self.ql.log.debug(f'{key}:')

            for value in values:
                self.ql.log.debug(f'{json.dumps(value):s}')

        self.ql.log.debug("Registries accessed")
        for key, values in self.registry_manager.accessed.items():
            self.ql.log.debug(f'{key}:')

            for value in values:
                self.ql.log.debug(f'{json.dumps(value):s}')

        self.ql.log.debug("Strings")
        for key, values in self.utils.appeared_strings.items():
            self.ql.log.debug(f'{key}: {" ".join(str(word) for word in values)}')


    def run(self):
        if self.ql.exit_point is not None:
            self.exit_point = self.ql.exit_point

        if  self.ql.entry_point is not None:
            self.ql.loader.entry_point = self.ql.entry_point

        if self.ql.stdin != 0:
            self.stdin = self.ql.stdin

        if self.ql.stdout != 0:
            self.stdout = self.ql.stdout

        if self.ql.stderr != 0:
            self.stderr = self.ql.stderr

        try:
            if self.ql.code:
                self.ql.emu_start(self.ql.loader.entry_point, (self.ql.loader.entry_point + len(self.ql.code)), self.ql.timeout, self.ql.count)
            else:
                self.ql.emu_start(self.ql.loader.entry_point, self.exit_point, self.ql.timeout, self.ql.count)
        except UcError:
            self.emu_error()
            raise

        self.registry_manager.save()
        self.post_report()
