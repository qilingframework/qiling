#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import os

from qiling.const import *

def ql_syscall_getrandom(ql, buf, buflen, flags,*args, **kw):
    data = None
    regreturn = None
    try:
        data = os.urandom(buflen)
        ql.uc.mem_write(buf, data)
        regreturn = len(data)
    except:
        regreturn = -1

    ql.nprint("getrandom(0x%x, 0x%x, 0x%x) = %d" %
              (buf, buflen, flags, regreturn))

    if data:
        ql.dprint(D_CTNT, "[+] getrandom() CONTENT:")
        ql.dprint(D_CTNT, str(data))
    ql.os.definesyscall_return(regreturn)
