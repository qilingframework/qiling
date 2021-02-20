#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.const import QL_INTERCEPT
from qiling.exception import QlErrorSyscallError, QlErrorSyscallNotFound

# hook Linux kernel API
def hook_kernel_api(ql: Qiling, address: int, size):
    # call kernel api
    if address in ql.loader.import_symbols:
        api_name = ql.loader.import_symbols[address]
        # print("OK, found hook for %s" %api_name)

        api_func = ql.os.user_defined_api[QL_INTERCEPT.CALL].get(api_name)

        if not api_func:
            api_func = globals().get(f'hook_{api_name}')

        ql.os.api_func_onenter = ql.os.user_defined_api[QL_INTERCEPT.ENTER].get(api_name)
        ql.os.api_func_onexit = ql.os.user_defined_api[QL_INTERCEPT.EXIT].get(api_name)

        if api_func:
            try:
                api_func(ql, address, {})
            except Exception:
                ql.log.exception("")
                ql.log.debug("%s Exception Found" % api_name)
                raise QlErrorSyscallError("Linux kernel API Implementation Error")
        else:
            ql.log.warning("%s is not implemented\n" % api_name)
            if ql.debug_stop:
                raise QlErrorSyscallNotFound("Linux kernel API Implementation Not Found")
