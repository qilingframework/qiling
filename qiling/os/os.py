#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import os, sys

from qiling.utils import ql_ostype_convert_str
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

        if self.ql.stdin != 0:
            self.stdin = self.ql.stdin
        
        if self.ql.stdout != 0:
            self.stdout = self.ql.stdout
        
        if self.ql.stderr != 0:
            self.stderr = self.ql.stderr

        # define analysis enviroment profile
        if not self.ql.profile:
            self.profile = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".." ,"profiles", ql_ostype_convert_str(self.ql.ostype) + ".ql")

        if self.ql.archbit == 32:
            self.QL_EMU_END = QL_ARCHBIT32_EMU_END
        elif self.ql.archbit == 64:
            self.QL_EMU_END = QL_ARCHBIT64_EMU_END           

