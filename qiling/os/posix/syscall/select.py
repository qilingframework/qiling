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


def ql_syscall__newselect(ql, _newselect_nfds, _newselect_readfds, _newselect_writefds, _newselect_exceptfds, _newselect_timeout, *args, **kw):

    regreturn = 0

    def parse_fd_set(ql, max_fd, struct_addr):
        fd_list = []
        fd_map = {}
        idx = 0
        tmp = 0
        if struct_addr == 0:
            return fd_list, fd_map
        while idx < max_fd:
            if idx % 32 == 0:
                tmp = ql.unpack32(ql.mem.read(struct_addr + idx, 4))
            if tmp & 0x1 != 0:
                fd_list.append(ql.file_des[idx].socket)
                fd_map[ql.file_des[idx].socket] = idx
            tmp = tmp >> 1
            idx += 1
        return fd_list, fd_map

    def set_fd_set(buf, idx):
        buf = buf[ : idx // 8] + bytes([buf[idx // 8] | (0x1 << (idx % 8))]) + buf[idx // 8 + 1 : ]
        return buf

    tmp_r_fd, tmp_r_map = parse_fd_set(ql, _newselect_nfds, _newselect_readfds)
    tmp_w_fd, tmp_w_map = parse_fd_set(ql, _newselect_nfds, _newselect_writefds)
    tmp_e_fd, tmp_e_map = parse_fd_set(ql, _newselect_nfds, _newselect_exceptfds)

    timeout = ql.unpack32(ql.mem.read(_newselect_timeout, 4))
    try:
        ans = select.select(tmp_r_fd, tmp_w_fd, tmp_e_fd, timeout)
        regreturn = len(ans[0]) + len(ans[1]) + len(ans[2])

        if _newselect_readfds != 0:
            tmp_buf = b'\x00' * (_newselect_nfds // 8 + 1)
            for i in ans[0]:
                ql.dprint(D_INFO, "debug : " + str(tmp_r_map[i]))
                tmp_buf = set_fd_set(tmp_buf, tmp_r_map[i])
            ql.mem.write(_newselect_readfds, tmp_buf)

        if _newselect_writefds != 0:
            tmp_buf = b'\x00' * (_newselect_nfds // 8 + 1)
            for i in ans[1]:
                tmp_buf = set_fd_set(tmp_buf, tmp_w_map[i])
            ql.mem.write(_newselect_writefds, tmp_buf)

        if _newselect_exceptfds != 0:
            tmp_buf = b'\x00' * (_newselect_nfds // 8 + 1)
            for i in ans[2]:
                tmp_buf = set_fd_set(tmp_buf, tmp_e_map[i])
            ql.mem.write(_newselect_exceptfds, tmp_buf)
    except KeyboardInterrupt:
        raise
    except:
        if ql.output in (QL_OUT_DEBUG, QL_OUT_DUMP):
            raise
    ql.nprint("_newselect(%d, %x, %x, %x, %x) = %d" % (_newselect_nfds, _newselect_readfds, _newselect_writefds, _newselect_exceptfds, _newselect_timeout, regreturn))
    ql_definesyscall_return(ql, regreturn)
