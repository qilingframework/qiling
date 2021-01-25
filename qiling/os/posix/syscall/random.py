#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

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

    ql.log.info("getrandom(0x%x, 0x%x, 0x%x) = %d" %
              (buf, buflen, flags, regreturn))

    if data:
        ql.log.debug("[+] getrandom() CONTENT:")
        ql.log.debug(str(data))
    return regreturn
