#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import types

from unicorn import *

from qiling.arch.x86_const import *
from qiling.arch.x86 import *
from qiling.os.utils import *
from qiling.const import *

#from qiling.loader.pe import PELoader
from qiling.os.windows.dlls import *
from qiling.os.windows.const import *
from qiling.os.windows.const import Mapper
from qiling.os.memory import QlMemoryHeap
from qiling.os.windows.utils import *

from qiling.os.os import QlOs


class QlOsWindows(QlOs):
    def __init__(self, ql):
        QlOs.__init__(self, ql)
        self.ql = ql
        self.PE_RUN = True
        self.last_error = 0
        # variables used inside hooks
        self.user_defined_api = {}
        self.hooks_variables = {}
        self.syscall_count = {}
        self.load()

    def load(self):
        """
        initiate UC needs to be in loader, or else it will kill execve
        Note: This is Windows, but for the sake of same with others OS
        """
        self.ql.uc = self.ql.arch.init_uc

        self.ql.hook_mem_unmapped(ql_x86_windows_hook_mem_error)

        if self.ql.archtype == QL_X8664:
            self.stack_address = 0x7ffffffde000
            self.stack_size = 0x40000
            self.ql.code_address = 0x140000000
            self.ql.code_size = 10 * 1024 * 1024
            self.HEAP_BASE_ADDR = 0x500000000
            self.HEAP_SIZE = 0x5000000            
        elif self.ql.archtype == QL_X86:
            self.stack_address = 0xfffdd000
            self.stack_size = 0x21000
            self.ql.code_address = 0x40000
            self.ql.code_size = 10 * 1024 * 1024
            self.HEAP_BASE_ADDR = 0x5000000
            self.HEAP_SIZE = 0x5000000

        if self.ql.stack_address == 0:
            self.ql.stack_address = self.stack_address
        if self.ql.stack_size == 0:
            self.ql.stack_size = self.stack_size
        """
        Load Heap module
        FIXME: We need to refactor this
        """
        self.heap = QlMemoryHeap(
                self.ql,
                self.HEAP_BASE_ADDR,
                self.HEAP_BASE_ADDR + self.HEAP_SIZE)

        self.setupGDT()
        # hook win api
        self.ql.hook_code(self.hook_winapi)

    def setupGDT(self):
        # setup gdt
        if self.ql.archtype == QL_X86:
            self.gdtm = GDTManager(self.ql)
            ql_x86_register_cs(self)
            ql_x86_register_ds_ss_es(self)
            ql_x86_register_fs(self)
            ql_x86_register_gs(self)
        elif self.ql.archtype == QL_X8664:
            ql_x8664_set_gs(self.ql)

    def setupComponents(self):
        # user configuration
        self.profile = ql_init_configuration(self)
        # handle manager
        self.handle_manager = HandleManager()
        # registry manger
        self.registry_manager = RegistryManager(self.ql)
        # clipboard
        self.clipboard = Clipboard(self.ql)
        # fibers
        self.fiber_manager = FiberManager(self.ql)
        # thread manager
        main_thread = QlWindowsThread(self.ql)
        self.thread_manager = QlWindowsThreadManagement(self.ql, main_thread)

        # more handle manager
        new_handle = Handle(thread=main_thread)
        self.handle_manager.append(new_handle)

    # hook WinAPI in PE EMU
    def hook_winapi(self, int, address, size):
        if address in self.ql.loader.import_symbols:
            winapi_name = self.ql.loader.import_symbols[address]['name']
            if winapi_name is None:
                winapi_name = Mapper[self.ql.loader.import_symbols[address]['dll']][self.ql.loader.import_symbols[address]['ordinal']]
            else:
                winapi_name = winapi_name.decode()
            winapi_func = None

            if winapi_name in self.user_defined_api:
                if isinstance(self.user_defined_api[winapi_name], types.FunctionType):
                    winapi_func = self.user_defined_api[winapi_name]
            else:
                try:
                    counter = self.syscall_count.get(winapi_name, 0) + 1
                    self.syscall_count[winapi_name] = counter
                    winapi_func = globals()['hook_' + winapi_name]
                except KeyError:
                    winapi_func = None

            if winapi_func:
                try:
                    winapi_func(self, address, {})
                except Exception:
                    self.ql.nprint("[!] %s Exception Found" % winapi_name)
                    raise QlErrorSyscallError("[!] Windows API Implementation Error")
            else:
                self.ql.nprint("[!] %s is not implemented\n" % winapi_name)
                if self.ql.debug_stop:
                    raise QlErrorSyscallNotFound("[!] Windows API Implementation Not Found")

    def run(self):

        ql_setup_output(self.ql)

        if (self.ql.until_addr == 0):
            self.ql.until_addr = self.QL_EMU_END
        try:
            if self.ql.shellcoder:
                self.ql.uc.emu_start(self.ql.code_address, self.ql.code_address + len(self.ql.shellcoder))
            else:
                self.ql.uc.emu_start(self.ql.entry_point, self.ql.until_addr, self.ql.timeout)
        except UcError:
            if self.ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
                self.ql.nprint("[+] PC = 0x%x\n" % (self.ql.pc))
                self.ql.mem.show_mapinfo()
                try:
                    buf = self.ql.mem.read(self.ql.pc, 8)
                    self.ql.nprint("[+] %r" % ([hex(_) for _ in buf]))
                    self.ql.nprint("\n")
                    ql_hook_code_disasm(self.ql, self.ql.pc, 64)
                except:
                    pass
            raise

        self.registry_manager.save()

        post_report(self)

        if self.ql.internal_exception is not None:
            raise self.ql.internal_exception
