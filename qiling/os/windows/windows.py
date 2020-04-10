#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import types

from unicorn import *

from qiling.arch.x86_const import *
from qiling.os.utils import *
from qiling.const import *

from qiling.loader.pe import LoaderPE
from qiling.os.windows.dlls import *
from qiling.os.windows.const import *
from qiling.os.windows.const import Mapper

from qiling.os.os import QlOs

class QlOsWindows(QlOs):
    def __init__(self, ql):
        super(QlOsWindows, self).__init__(ql)
        self.ql = ql
        self.user_defined_api = {}
        self.PE_RUN = True
        self.last_error = 0
        # variables used inside hooks
        self.hooks_variables = {}
        self.syscall_count = {}  
        self.load()

    def load(self):        

        """
        initiate UC needs to be in loader, or else it will kill execve
        Note: This is Windows, but for the sake of same with others OS
        """
        self.ql.uc = self.ql.arch.init_uc

        if self.ql.archtype== QL_X8664:
            self.QL_WINDOWS_STACK_ADDRESS = 0x7ffffffde000
            self.QL_WINDOWS_STACK_SIZE = 0x40000
            self.ql.code_address = 0x140000000
            self.ql.code_size = 10 * 1024 * 1024
        elif self.ql.archtype== QL_X86:        
            self.QL_WINDOWS_STACK_ADDRESS = 0xfffdd000
            self.QL_WINDOWS_STACK_SIZE =0x21000 
            self.ql.code_address = 0x40000
            self.ql.code_size = 10 * 1024 * 1024

        if self.ql.stack_address == 0:
            self.ql.stack_address = self.QL_WINDOWS_STACK_ADDRESS
        if self.ql.stack_size == 0:
            self.ql.stack_size = self.QL_WINDOWS_STACK_SIZE            

        if self.ql.path and not self.ql.shellcoder:
            self.LoaderPE = LoaderPE(self.ql, path =self.ql.path)
        else:     
            self.LoaderPE = LoaderPE(self.ql, dlls= [b"ntdll.dll", b"kernel32.dll", b"user32.dll"])
        
        # due to init memory mapping
        # setup() must come before loader.load() and afer setting up loader
        setup(self)

        # after setup the ENV
        self.LoaderPE.load()
        # hook win api
        self.ql.hook_code(self.hook_winapi)


    # hook WinAPI in PE EMU
    def hook_winapi(self, int, address, size):
        if address in self.LoaderPE.import_symbols:
            winapi_name = self.LoaderPE.import_symbols[address]['name']
            if winapi_name is None:
                winapi_name = Mapper[self.LoaderPE.import_symbols[address]['dll']][self.LoaderPE.import_symbols[address]['ordinal']]
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
                    self.ql.dprint(D_PROT, "[!] %s Exception Found" % winapi_name)
                    raise QlErrorSyscallError("[!] Windows API Implementation Error")
            else:
                self.ql.nprint("[!] %s is not implemented\n" % winapi_name)
                if self.ql.debug_stop:
                    raise QlErrorSyscallNotFound("[!] Windows API Implementation Not Found")


    def run(self):
        ql_setup_output(self.ql)

        if self.ql.until_addr == 0:
            if self.ql.archbit == 32:
                self.ql.until_addr = QL_ARCHBIT32_EMU_END
            else:
                self.ql.until_addr = QL_ARCHBIT64_EMU_END            
        try:
            if self.ql.shellcoder:
                self.ql.uc.emu_start(self.ql.code_address, self.ql.code_address + len(self.ql.shellcoder))
            else:
                self.ql.uc.emu_start(self.ql.entry_point, self.ql.until_addr, self.ql.timeout)
        except UcError:
            if self.ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
                self.ql.nprint("[+] PC = 0x%x\n" %(self.ql.pc))
                self.ql.mem.show_mapinfo()
                try:
                    buf = ql.mem.read(ql.pc, 8)
                    self.ql.nprint("[+] %r" % ([hex(_) for _ in buf]))
                    self.ql.nprint("\n")
                    ql_hook_code_disasm(ql, ql.pc, 64)
                except:
                    pass
            raise

        self.registry_manager.save()

        post_report(self)

        if self.ql.internal_exception is not None:
            raise self.ql.internal_exception
