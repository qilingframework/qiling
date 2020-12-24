#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import os, logging

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

    logging.info("getrandom(0x%x, 0x%x, 0x%x) = %d" %
              (buf, buflen, flags, regreturn))

    if data:
        logging.debug("[+] getrandom() CONTENT:")
        logging.debug(str(data))
    ql.os.definesyscall_return(regreturn)
