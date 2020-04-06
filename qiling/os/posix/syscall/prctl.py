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

def ql_syscall_arch_prctl(ql, ARCHX, ARCH_SET_FS, *args, **kw):
    FSMSR = 0xC0000100
    ql.uc.msr_write(FSMSR, ARCH_SET_FS)
    regreturn = 0
    ql.nprint("arch_prctl(0x%x) = %d" % (ARCH_SET_FS, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_prctl(ql, *args, **kw):
    regreturn = 0
    ql.nprint("prctl() = %d" % (regreturn))
    ql_definesyscall_return(ql, regreturn)
