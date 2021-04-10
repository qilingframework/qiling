#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_INTERCEPT
from qiling.os.windows.fncc import *
from qiling.os.const import STRING
from qiling.const import QL_VERBOSE

@winsdkapi(cc=CDECL, replace_params={"str": STRING}) 
def my_puts(ql: Qiling, address: int, params):
    ql.log.info(f'puts was overriden by this hook')

    # puts is expected to return the string length
    return len(params["str"])

def my_onenter(ql: Qiling, address: int, params):
    print(f'[onenter] _cexit : params = {params}')

    # return an alternative set of parameters to be used by the
    # actual function, that will execute as soon as this one returns
    params = {
        'hKey'      : 0x80000001,
        'lpSubKey'  : 'Software',
        'phkResult' : 0xffffcfb4
    }

    return address, params

def my_onexit(ql: Qiling, address: int, params, retval: int):
    print(f'[onexit] atexit : params = {params}')

def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs, verbose=QL_VERBOSE.DEBUG)

    ql.set_api("_cexit", my_onenter, QL_INTERCEPT.ENTER)
    ql.set_api("puts", my_puts)
    ql.set_api("atexit", my_onexit, QL_INTERCEPT.EXIT)

    ql.run()

if __name__ == "__main__":
    my_sandbox(["rootfs/x8664_windows/bin/x8664_hello.exe"], "rootfs/x8664_windows")
