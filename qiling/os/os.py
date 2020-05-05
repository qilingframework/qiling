#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import os, sys

from .utils import QLOsUtils
from .const import *
from .filestruct import ql_file

class QlOs(QLOsUtils):
    def __init__(self, ql):
        super(QlOs, self).__init__(ql)
        self.ql = ql
        self.stdin = ql_file('stdin', sys.stdin.fileno())
        self.stdout = ql_file('stdout', sys.stdout.fileno())
        self.stderr = ql_file('stderr', sys.stderr.fileno())
        self.child_processes = False
        self.thread_management = None
        self.current_path = '/'
        self.profile = self.ql.profile
        self.exit_code = 0

        if self.ql.stdin != 0:
            self.stdin = self.ql.stdin
        
        if self.ql.stdout != 0:
            self.stdout = self.ql.stdout
        
        if self.ql.stderr != 0:
            self.stderr = self.ql.stderr

        if self.ql.archbit == 32:
            EMU_END = 0x8fffffff
        elif self.ql.archbit == 64:
            EMU_END = 0xffffffffffffffff        
        
        # defult exit point
        self.exit_point = EMU_END

        if self.ql.shellcoder:
            self.shellcoder_ram_size = int(self.profile.get("SHELLCODER", "ram_size"),16)
            # this shellcode entrypoint does not work for windows
            # windows shellcode entry point will comes from pe loader
            self.entry_point = int(self.profile.get("SHELLCODER", "entry_point"),16)

        # We can save every syscall called
        self.syscalls = {}
        self.syscalls_counter = 0
        self.appeared_strings = {}
