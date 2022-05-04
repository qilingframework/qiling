#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from unicorn import UcError
from unicorn.x86_const import UC_X86_INS_SYSCALL

from qiling.arch.x86_utils import GDTManager, SegmentManager86
from qiling.const import QL_OS
from qiling.os.posix.posix import QlOsPosix

class QlOsFreebsd(QlOsPosix):
    type = QL_OS.FREEBSD

    def __init__(self, ql):
        super(QlOsFreebsd, self).__init__(ql)

        self.elf_mem_start = 0x0
        self.load()


    def load(self):
        gdtm = GDTManager(self.ql)

        # setup gdt and segments selectors
        segm = SegmentManager86(self.ql.arch, gdtm)
        segm.setup_cs_ds_ss_es(0, 4 << 30)

        self.ql.hook_insn(self.hook_syscall, UC_X86_INS_SYSCALL)


    def hook_syscall(self, ql):
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
                    self.ql.do_lib_patch()

                self.ql.emu_start(self.ql.loader.elf_entry, self.exit_point, self.ql.timeout, self.ql.count)

        except UcError:
            self.emu_error()
            raise
