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
import fcntl
import resource
import socket
import time
import io
import fcntl
import select

from unicorn import *
from unicorn.arm_const import *
from unicorn.x86_const import *
from unicorn.arm64_const import *
from unicorn.mips_const import *

# impport read_string and other commom utils.
from qiling.os.utils import *
from qiling.arch.filetype import *


def ql_syscall_clock_gettime(ql, uc, clock_gettime_clock_id, clock_gettime_timespec, null2, null3, null4, null5):
    ql.nprint("clock_gettime()")
    regreturn = 0
    ql_definesyscall_return(ql, uc, regreturn)


