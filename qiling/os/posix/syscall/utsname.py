#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#


from qiling.const import *
from qiling.os.linux.thread import *
from qiling.const import *
from qiling.os.posix.filestruct import *
from qiling.os.filestruct import *
from qiling.os.posix.const_mapping import *
from qiling.exception import *

def ql_syscall_uname(ql, address, *args, **kw):
    buf =  b''
    buf += b'QilingOS'.ljust(65, b'\x00')
    buf += b'ql_vm'.ljust(65, b'\x00')
    buf += b'99.0-RELEASE'.ljust(65, b'\x00')
    buf += b'QiligOS 99.0-RELEASE r1'.ljust(65, b'\x00')
    buf += b'ql_processor'.ljust(65, b'\x00')
    buf += b''.ljust(65, b'\x00')
    ql.mem.write(address, buf)
    regreturn = 0
    return regreturn
