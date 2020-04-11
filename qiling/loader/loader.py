#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from qiling.const import *
from qiling.arch.x86_const import *
from qiling.os.macos.utils import *
from qiling.os.macos.const import *
from qiling.os.memory import Heap
from qiling.loader.utils import *


class QlLoader:
    def __init__(self, ql):
        self.ql = ql
        self.load()

    def load(self):
        #loader = ql_loader_setup(self.ql, self.ql.ostype)
        if self.ql.ostype == QL_MACOS:
            if not self.ql.shellcoder:
                from qiling.loader.macho import QlLoaderMacho
                self.er = QlLoaderMacho(self.ql, self.ql.path, self.ql.os.stack_sp, [self.ql.path], self.ql.os.envs, self.ql.os.apples, 1)
                self.er.loadMacho()
                self.ql.os.macho_task.min_offset = page_align_end(self.er.vm_end_addr, PAGE_SIZE)
                self.ql.stack_address = (int(self.ql.stack_sp))
            
        elif self.ql.ostype == QL_WINDOWS:
            from qiling.loader.pe import QlLoaderPE
            if self.ql.path and not self.ql.shellcoder:
                self.er = QlLoaderPE(self.ql, path=self.ql.path)
                #print(type(loader))
                #self.er = loader(self.ql, path=self.ql.path)
            else:
                self.er = QlLoaderPE(self.ql, dlls=[b"ntdll.dll", b"kernel32.dll", b"user32.dll"])

            self.ql.heap = Heap(
                self.ql,
                self.er.HEAP_BASE_ADDR,
                self.er.HEAP_BASE_ADDR + self.er.HEAP_SIZE
            )
            self.ql.os.setupComponents()
            self.er.load()

        elif self.ql.ostype in (QL_LINUX, QL_FREEBSD):
            if not self.ql.shellcoder:
                from qiling.loader.elf import QlLoaderELF
                self.er = QlLoaderELF(self.ql.path, self.ql)
                if self.er.load_with_ld(self.ql, self.ql.stack_address + self.ql.stack_size, argv = self.ql.argv, env = self.ql.env):
                    raise QlErrorFileType("Unsupported FileType")
                self.ql.stack_address  = (int(self.ql.new_stack))




