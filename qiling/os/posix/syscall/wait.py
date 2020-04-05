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

def ql_syscall_wait4(ql, wait4_pid, wait4_wstatus, wait4_options, wait4_rusage, *args, **kw):
    spid, status, rusage = os.wait4(wait4_pid, wait4_options)
    ql.mem.write(wait4_wstatus, ql.pack32(status))
    regreturn = spid
    ql.nprint("wait4(%d, %d) = %d"% (wait4_pid, wait4_options, regreturn))
    ql_definesyscall_return(ql, regreturn)
