#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn import UcError

from qiling.arch.x86 import GDTManager, ql_x86_register_cs, ql_x86_register_ds_ss_es
from qiling.arch.x86_const import UC_X86_INS_SYSCALL
from qiling.os.posix.posix import QlOsPosix

class QlOsFreebsd(QlOsPosix):
    def __init__(self, ql):
        super(QlOsFreebsd, self).__init__(ql)

        self.elf_mem_start = 0x0
        self.load()


    def load(self):
        self.ql.hook_insn(self.hook_syscall, UC_X86_INS_SYSCALL)
        self.gdtm = GDTManager(self.ql)
        ql_x86_register_cs(self)
        ql_x86_register_ds_ss_es(self)


    def hook_syscall(self, intno= None):
        return self.load_syscall()


    def run(self):
        if self.ql.exit_point is not None:
            self.exit_point = self.ql.exit_point

        if  self.ql.entry_point is not None:
            self.ql.loader.elf_entry = self.ql.entry_point

        try:
            if self.ql.code:
                self.ql.emu_start(self.entry_point, (self.entry_point + len(self.ql.code)), self.ql.timeout, self.ql.count)
            else:
                if self.ql.loader.elf_entry != self.ql.loader.entry_point:
                    self.ql.emu_start(self.ql.loader.entry_point, self.ql.loader.elf_entry, self.ql.timeout)
                    self.ql.enable_lib_patch()

                self.ql.emu_start(self.ql.loader.elf_entry, self.exit_point, self.ql.timeout, self.ql.count)

        except UcError:
            self.emu_error()
            raise
