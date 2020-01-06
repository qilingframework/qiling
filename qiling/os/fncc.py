#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

# function calling convention

from unicorn.x86_const import *
from qiling.os.windows.fncc import *
from qiling.exception import *


STDCALL = 1
CDECL = 2
