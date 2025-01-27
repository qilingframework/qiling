#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.const import QL_INTERCEPT, QL_ARCH
from qiling.exception import QlErrorSyscallError, QlErrorSyscallNotFound

# import all kernel api hooks to global namespace
import qiling.os.linux.kernel_api as api

# hook Linux kernel API
def hook_kernel_api(ql: Qiling, address: int, size):
    # call kernel api
    if address in ql.loader.import_symbols:
        api_name = ql.loader.import_symbols[address]
        # print("OK, found hook for %s" %api_name)

        api_func = ql.os.user_defined_api[QL_INTERCEPT.CALL].get(api_name)

        if not api_func:
            api_func = getattr(api, f'hook_{api_name}', None)

        if api_func:
            try:
                api_func(ql, address, api_name)

                # Restore PC
                if ql.arch.type == QL_ARCH.ARM:
                    ql.arch.regs.arch_sp -= ql.arch.pointersize
                    ql.arch.regs.arch_pc = ql.arch.regs.lr
            except Exception:
                ql.log.exception("")
                ql.log.debug("%s Exception Found" % api_name)
                raise QlErrorSyscallError("Linux kernel API Implementation Error")
        else:
            ql.log.warning(f'api {api_name} is not implemented')

            if ql.debug_stop:
                raise QlErrorSyscallNotFound("Linux kernel API implementation not found")
