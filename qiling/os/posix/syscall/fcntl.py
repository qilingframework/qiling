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

def ql_syscall_open(ql, filename, flags, mode, *args, **kw):
    path = ql_read_string(ql, filename)
    real_path = ql_transform_to_real_path(ql, path)
    relative_path = ql_transform_to_relative_path(ql, path)

    flags = flags & 0xffffffff
    mode = mode & 0xffffffff

    for i in range(256):
        if ql.file_des[i] == 0:
            idx = i
            break
    else:
        idx = -1

    if idx == -1:
        regreturn = -1
    else:
        try:
            if ql.arch == QL_ARM:
                mode = 0

            flags = ql_open_flag_mapping(flags, ql)
            ql.file_des[idx] = ql_file.open(real_path, flags, mode)
            regreturn = idx
        except:
            regreturn = -1

    ql.nprint("open(%s, 0x%x, 0o%o) = %d" % (relative_path, flags, mode, regreturn))
    ql.dprint(1, "[+] open(%s, %s, 0o%o) = %d" % (relative_path, open_flags_mapping(flags, ql.arch), mode, regreturn))

    if regreturn >= 0 and regreturn != 2:
        ql.dprint(0, "[+] File Found: %s" % relative_path)
    else:
        ql.dprint(0, "[!] File Not Found %s" % relative_path)
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_openat(ql, openat_fd, openat_path, openat_flags, openat_mode, *args, **kw):
    openat_fd = ql.unpacks(ql.pack(openat_fd))
    openat_path = ql_read_string(ql, openat_path)

    real_path = ql_transform_to_real_path(ql, openat_path)
    relative_path = ql_transform_to_relative_path(ql, openat_path)

    openat_flags = openat_flags & 0xffffffff
    openat_mode = openat_mode & 0xffffffff

    for i in range(256):
        if ql.file_des[i] == 0:
            idx = i
            break
    else:
        idx = -1

    if idx == -1:
        regreturn = -1
    else:
        try:
            if ql.arch == QL_ARM:
                mode = 0

            openat_flags = ql_open_flag_mapping(openat_flags, ql)
            ql.file_des[idx] = ql_file.open(real_path, openat_flags, openat_mode)
            regreturn = idx
        except:
            regreturn = -1

    ql.nprint("openat(%d, %s, 0x%x, 0o%o) = %d" % (openat_fd, relative_path, openat_flags, openat_mode, regreturn))
    ql.dprint(1, "[+] openat(%d, %s, %s, 0o%o) = %d" % (
    openat_fd, relative_path, open_flags_mapping(openat_flags, ql.arch), openat_mode, regreturn))

    if regreturn >= 0 and regreturn != 2:
        ql.dprint(0, "[+] File Found: %s" % relative_path)
    else:
        ql.dprint(0, "[!] File Not Found %s" % relative_path)
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_fcntl(ql, fcntl_fd, fcntl_cmd, *args, **kw):
    F_SETFD = 2
    F_GETFL = 3
    F_SETFL = 4
    regreturn = 0
    if fcntl_cmd == F_SETFD:
        regreturn = 0
    elif fcntl_cmd == F_GETFL:
        regreturn = 2
    elif fcntl_cmd == F_SETFL:
        regreturn = 0

    ql.nprint("fcntl(%d, %d) = %d" % (fcntl_fd, fcntl_cmd, regreturn))
    ql_definesyscall_return(ql, regreturn)


def ql_syscall_fcntl64(ql, fcntl_fd, fcntl_cmd, fcntl_arg, null1, null2, null3):

    F_GETFD = 1
    F_SETFD = 2
    F_GETFL = 3
    F_SETFL = 4

    if fcntl_cmd == F_GETFL:
        regreturn = 2
    elif fcntl_cmd == F_SETFL:
        regreturn = 0
    elif fcntl_cmd == F_GETFD:
        regreturn = 2
    elif fcntl_cmd == F_SETFD:
        regreturn = 0
    else:
        regreturn = 0

    ql.nprint("fcntl64(%d, %d, %d) = %d" % (fcntl_fd, fcntl_cmd, fcntl_arg, regreturn))
    ql_definesyscall_return(ql, regreturn)
