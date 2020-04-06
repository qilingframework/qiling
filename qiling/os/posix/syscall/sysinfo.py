#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)
import struct
import sys
import os
import stat
import string
import resource
import socket
import time
import io
import select
import pathlib
import logging
import itertools

# Remove import fcntl due to Windows Limitation
#import fcntl

from unicorn import *
from unicorn.arm_const import *
from unicorn.x86_const import *
from unicorn.arm64_const import *
from unicorn.mips_const import *

# impport read_string and other commom utils.
from qiling.os.utils import *
from qiling.const import *
from qiling.os.linux.thread import *
from qiling.const import *
from qiling.os.posix.filestruct import *
from qiling.os.posix.const_mapping import *
from qiling.utils import *

def ql_syscall_sysinfo(ql, sysinfo_info, *args, **kw):

    data = b''
    data += struct.pack("QQQQQQQQQQHQQI",
                       0x1234, # uptime
                       0x2000, # loads (1 min)
                       0x2000, # loads (5 min)
                       0x2000, # loads (15 min)
                       0x10000000, # total ram
                       0x10000000, # free ram
                       0x10000000, # shared memory
                       0x0, # memory used by buffers
                       0x0, # total swap
                       0x0, # free swap
                       0x1, # nb current processes
                       0x0, # total high mem
                       0x0, # available high mem
                       0x1, # memory unit size
    )

    regreturn = 0
    ql.nprint("sysinfo(0x%x) = %d" % (sysinfo_info, regreturn))
    #uc.mem_write(sysinfo_info, data)
    ql_definesyscall_return(ql, regreturn)
