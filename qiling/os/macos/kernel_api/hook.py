#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

from qiling.os.macos.kernel_api import *
from unicorn import *

# hook MacOS kernel API
def hook_kernel_api(ql, address, size):
    # call kernel api
    if address in ql.import_symbols:
        api_name = ql.import_symbols[address].decode()
        # print("OK, found hook for %s at 0x%x" % (api_name, address))
        api_func = None

        if api_name in ql.os.user_defined_api:
            if isinstance(ql.os.user_defined_api[api_name], types.FunctionType):
                api_func = ql.os.user_defined_api[api_name]
        else:
            try:
                api_func = globals()['hook_' + api_name]
            except KeyError:
                api_func = None

        if api_func:
            try:
                api_func(ql, address, {})
            except UcError:
                raise
            except Exception:
                ql.dprint(D_INFO, "[!] %s Exception Found" % api_name)
                raise QlErrorSyscallError("[!] MacOS kernel API Implementation Error")
        else:
            ql.nprint("[!] %s is not implemented\n" % api_name)
            if ql.debug_stop:
                raise QlErrorSyscallNotFound("[!] MacOS kernel API Implementation Not Found")


