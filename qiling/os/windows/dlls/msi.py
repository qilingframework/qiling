#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
#
# LAU kaijern (xwings) <kj@qiling.io>
# NGUYEN Anh Quynh <aquynh@gmail.com>
# DING tianZe (D1iv3) <dddliv3@gmail.com>
# SUN bowen (w1tcher) <w1tcher.bupt@gmail.com>
# CHEN huitao (null) <null@qiling.io>
# YU tong (sp1ke) <spikeinhouse@gmail.com>

import struct
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *
from qiling.os.windows.memory import align
from qiling.os.windows.thread import *
from qiling.os.windows.handle import *
from qiling.exception import *

#UINT MSI_GetComponentStateA 	( 	
#       MSIPACKAGE *  	    package,
#		LPCSTR  	        szComponent,
#		INSTALLSTATE *  	piInstalled,
#		INSTALLSTATE *  	piAction 
#	); 	
@winapi(x86=X86_STDCALL, x8664=X8664_FASTCALL, params={
    "package": POINTER,
    "szComponent": STRING,
    "piInstalled": POINTER,
    "piAction": POINTER
})
def hook_MsiGetComponentStateA(ql, address, params):
    print("hook_MsiGetComponentStateA")
    return 6 #INVALID_HANDLE
