#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

from qiling.os.macos.mach_port import *

# TODO: finished
class MachoThread():

    def __init__(self):
        self.id = 123
        self.port = MachPort(0x307)