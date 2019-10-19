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
import sys
import os
import string
import resource
import socket
import time
import io
import select

from unicorn import *
from unicorn.arm_const import *
from unicorn.x86_const import *
from unicorn.arm64_const import *
from unicorn.mips_const import *

# impport read_string and other commom utils.
from qiling.os.utils import *
from qiling.arch.filetype import *
from qiling.arch.x86 import *

def ql_x86_syscall_set_thread_area(ql, uc, u_info_addr, null0, null1, null2, null3, null4):
    ql.nprint("set_thread_area(u_info_addr= 0x%x)" % u_info_addr)
    u_info = uc.mem_read(u_info_addr, 4 * 3)
    base = ql.unpack32(u_info[4 : 8])
    limit = ql.unpack32(u_info[8 : 12])
    ql.nprint("|-->>> set_thread_area base : 0x%x limit is : 0x%x" % (base, limit))
    ql_x86_setup_syscall_set_thread_area(ql, uc, base, limit)
    uc.mem_write(u_info_addr, ql.pack32(12))
    regreturn = 0
    ql_definesyscall_return(ql, uc, regreturn)

