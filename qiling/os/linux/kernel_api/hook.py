#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.os.linux.kernel_api import *


# hook Linux kernel API
def hook_kernel_api(ql, address, size):
    # call kernel api
    # print("check hook_kernel_api: %x" %(address))
    if address in ql.import_symbols:
        api_name = ql.import_symbols[address]
        # print("OK, found hook for %s" %api_name)
        api_func = None

        if api_name in ql.os.user_defined_api:
            if isinstance(ql.os.user_defined_api[api_name], types.FunctionType):
                api_func = ql.os.user_defined_api[api_name]
        else:
            try:
                api_func = globals()['hook_' + api_name]
            except KeyError:
                # print("ERROR on globals", globals())
                api_func = None

        if api_func:
            try:
                api_func(ql, address, {})
            except Exception:
                ql.log.exception("")
                ql.log.debug("[!] %s Exception Found" % api_name)
                raise QlErrorSyscallError("[!] Linux kernel API Implementation Error")
        else:
            ql.log.warning("[!] %s is not implemented\n" % api_name)
            if ql.debug_stop:
                raise QlErrorSyscallNotFound("[!] Linux kernel API Implementation Not Found")

