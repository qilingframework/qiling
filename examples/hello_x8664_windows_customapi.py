#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import sys
sys.path.append("..")

from qiling import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import *
from qiling.const import *

@winapi(cc=CDECL, params={
    "str": STRING
})
def my_puts(ql, address, params):
    ret = 0
    ql.nprint("\n+++++++++\nmy random Windows API\n+++++++++\n")
    string = params["str"]
    ret = len(string)
    return ret


def my_onenter(ql, address, params):
    print("\n+++++++++\nmy OnEnter")
    print("lpSubKey: %s" % params["lpSubKey"])
    params = ({'hKey': 2147483649, 'lpSubKey': 'Software', 'phkResult': 4294954932})
    print("+++++++++\n")
    return  address, params


def my_onexit(ql, address, params):
    print("\n+++++++++\nmy OnExit")
    print("params: %s" % params)
    print("+++++++++\n")


def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs, output = "debug")
    ql.set_api("_cexit", my_onenter, QL_INTERCEPT.ENTER)
    ql.set_api("puts", my_puts)
    ql.set_api("atexit", my_onexit, QL_INTERCEPT.EXIT)
    ql.run()

if __name__ == "__main__":
    my_sandbox(["rootfs/x8664_windows/bin/x8664_hello.exe"], "rootfs/x8664_windows")
