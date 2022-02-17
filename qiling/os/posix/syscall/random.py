#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os

from qiling import Qiling

def ql_syscall_getrandom(ql: Qiling, buf: int, buflen: int, flags: int):
    try:
        data = os.urandom(buflen)
        ql.mem.write(buf, data)
    except:
        retval = -1
    else:
        data_formated = ' '.join([f'{b:02X}' for b in data])
        ql.log.debug(f'getrandom() CONTENT: {data_formated}')
        retval = len(data)

    return retval
