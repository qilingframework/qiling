#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import os

from qiling.const import *
from .utils import *
from .const import *
from .posix.filestruct import *

class QlOs:
    def __init__(self, ql):
        self.ql = ql
        self.child_processes = False
        self.thread_management = None
        self.current_path = '/'
        self.stdin = ql_file('stdin', sys.stdin.fileno())
        self.stdout = ql_file('stdout', sys.stdout.fileno())
        self.stderr = ql_file('stderr', sys.stderr.fileno())

        if ql.stdin != 0:
            self.stdin = ql.stdin
        
        if ql.stdout != 0:
            self.stdout = ql.stdout
        
        if ql.stderr != 0:
            self.stderr = ql.stderr


        # define analysis enviroment profile
        if not self.ql.profile:
            self.profile = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".." ,"profiles", ql_ostype_convert_str(self.ql.ostype) + ".ql")

        if self.ql.archbit == 32:
            self.QL_EMU_END = QL_ARCHBIT32_EMU_END
        elif self.ql.archbit == 64:
            self.QL_EMU_END = QL_ARCHBIT64_EMU_END           


    def stop(self, stop_event=THREAD_EVENT_EXIT_GROUP_EVENT):
        if self.ql.multithread == True:
            td = self.thread_management.cur_thread
            td.stop()
            td.stop_event = stop_event
        self.ql.emu_stop()