#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import os
from qiling.os.thread import *
from qiling.os.macos.mach_port import *

# TODO: finished
class QlMachoThread(QlThread):

    def __init__(self, ql):
        super(QlMachoThread, self).__init__(ql)
        self.ql = ql
        self.id = 123
        self.port = MachPort(0x307)

    def stop(self):
        pass


class QlMachoThreadManagement(QlThreadManagement):

    def __init__(self, ql):
        super(QlMachoThreadManagement, self).__init__(ql)
        self.ql = ql
        self.cur_thread = None
