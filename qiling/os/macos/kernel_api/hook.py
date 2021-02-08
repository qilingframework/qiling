#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import types

from qiling.os.macos.kernel_api import *
from qiling.exception import *


# hook MacOS kernel API
def hook_kernel_api(ql, address, size):
    # call kernel api
    if address in ql.loader.import_symbols:
        api_name = ql.loader.import_symbols[address].decode()
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
                ql.log.exception("")
                ql.log.debug("%s Exception Found" % api_name)
                raise QlErrorSyscallError("MacOS kernel API Implementation Error")
        else:
            ql.log.info("%s is not implemented\n" % api_name)
            if ql.debug_stop:
                raise QlErrorSyscallNotFound("MacOS kernel API Implementation Not Found")


