#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import traceback

from unicorn import *
from unicorn.x86_const import *
from unicorn.arm64_const import *

from qiling.arch.x86 import *

from qiling.const import *
from qiling.os.const import *
from qiling.os.posix.posix import QlOsPosix

from .const import *

class QlOsMacos(QlOsPosix):
    def __init__(self, ql):
        super(QlOsMacos, self).__init__(ql)
        self.ql = ql
        self.load()

    def load(self):
        if self.ql.shellcoder:
            return

        if self.ql.archtype== QL_ARCH.ARM64:
            self.ql.arch.enable_vfp()
            self.ql.hook_intno(self.hook_syscall, 2)

        elif self.ql.archtype== QL_ARCH.X8664:
            self.ql.hook_insn(self.hook_syscall, UC_X86_INS_SYSCALL)
            self.gdtm = GDTManager(self.ql)
            ql_x86_register_cs(self)
            ql_x86_register_ds_ss_es(self)

    def hook_syscall(self, intno= None, int = None):
        return self.load_syscall()

    def run(self):
        if self.ql.exit_point is not None:
            self.exit_point = self.ql.exit_point

        if  self.ql.entry_point is not None:
                self.ql.loader.entry_point = self.ql.entry_point    

        try:
            if self.ql.shellcoder:
                self.ql.emu_start(self.entry_point, (self.entry_point + len(self.ql.shellcoder)), self.ql.timeout, self.ql.count)
            else:
                self.ql.emu_start(self.ql.loader.entry_point, self.exit_point, self.ql.timeout, self.ql.count)
        except UcError:
            if self.ql.output in (QL_OUTPUT.DEBUG, QL_OUTPUT.DUMP):
                self.ql.nprint("[+] PC = 0x%x" %(self.ql.reg.arch_pc))
                self.ql.mem.show_mapinfo()
                try:
                    buf = self.ql.mem.read(self.ql.reg.arch_pc, 8)
                    self.ql.nprint("[+] %r" % ([hex(_) for _ in buf]))
                    self.ql.nprint("\n")
                    self.disassembler(self.ql, self.ql.reg.arch_pc, 64)
                except:
                    pass
            raise

        if self.ql.internal_exception != None:
            raise self.ql.internal_exception
