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

def ql_syscall_ugetrlimit(ql, ugetrlimit_resource, ugetrlimit_rlim, *args, **kw):
    rlim = resource.getrlimit(ugetrlimit_resource)
    ql.mem.write(ugetrlimit_rlim, ql.pack32s(rlim[0]) + ql.pack32s(rlim[1]))
    regreturn = 0
    ql.nprint("ugetrlimit(%d, 0x%x) = %d" % (ugetrlimit_resource, ugetrlimit_rlim, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_setrlimit(ql, setrlimit_resource, setrlimit_rlim, *args, **kw):
    # maybe we can nop the setrlimit
    tmp_rlim = (ql.unpack32s(ql.mem.read(setrlimit_rlim, 4)), ql.unpack32s(ql.mem.read(setrlimit_rlim + 4, 4)))
    resource.setrlimit(setrlimit_resource, tmp_rlim)

    regreturn = 0
    ql.nprint("setrlimit(%d, 0x%x) = %d" % (setrlimit_resource, setrlimit_rlim, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_prlimit64(ql, pid, resource, new_limit, old_limit, *args, **kw):
    # setrlimit() and getrlimit()
    #if pid == 0:
    #    ql_syscall_setrlimit(ql, resource, new_limit, 0, 0, 0, 0);
    #    ql_syscall_ugetrlimit(ql, resource, old_limit, 0, 0, 0, 0);
    #    regreturn = 0;
    #else:
        # set other process which pid != 0
    #    regreturn = 0
    regreturn = 0
    #ql.nprint("prlimit64(%d, %d, 0x%x, 0x%x) = %d" % (pid, resource, new_limit, old_limit, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_getpriority(ql, getpriority_which, getpriority_who, null1, null2, null3, null4):
    base = os.getpriority(getpriority_which, getpriority_who)
    regreturn = base
    ql.nprint("getpriority(0x%x, 0x%x) = %d" % (getpriority_which, getpriority_who, regreturn))
    ql_definesyscall_return(ql, regreturn)
