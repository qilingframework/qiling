#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from unicorn.x86_const import *
from qiling.const import *

class QlWindowsManager:
    
    def __init__(self, ql):
        self.ql = ql