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

def ql_syscall_writev(ql, writev_fd, writev_vec, writev_vien, *args, **kw):
    regreturn = 0
    size_t_len = ql.archbit // 8
    iov = ql.mem.read(writev_vec, writev_vien * size_t_len * 2)
    ql.nprint("writev(0x%x, 0x%x, 0x%x)" % (writev_fd, writev_vec, writev_vien))
    if ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
        ql.dprint(D_INFO, "[+] writev() CONTENT:")
        for i in range(writev_vien):
            addr = ql.unpack(iov[i * size_t_len * 2 : i * size_t_len * 2 + size_t_len])
            l = ql.unpack(iov[i * size_t_len * 2 + size_t_len : i * size_t_len * 2 + size_t_len * 2])
            ql.dprint(D_INFO, "%s" % str(ql.mem.read(addr, l)))
    ql_definesyscall_return(ql, regreturn)
