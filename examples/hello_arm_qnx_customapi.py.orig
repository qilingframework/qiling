#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_INTERCEPT, QL_CALL_BLOCK
from qiling.os.const import STRING

def my_puts_onenter(ql: Qiling):
    params = ql.os.resolve_fcall_params({'s': STRING})

    print(f'puts("{params["s"]}")')

    return QL_CALL_BLOCK

def my_printf_onenter(ql: Qiling):
    params = ql.os.resolve_fcall_params({'s': STRING})

    print(f'printf("{params["s"]}")')

    return QL_CALL_BLOCK

def my_puts_onexit(ql: Qiling):
    print(f'after puts')

    return QL_CALL_BLOCK

if __name__ == "__main__":
    ql = Qiling(["rootfs/arm_qnx/bin/hello_static"], "rootfs/arm_qnx")
    ql.os.set_api('puts', my_puts_onenter, QL_INTERCEPT.ENTER)
    ql.os.set_api('printf', my_printf_onenter, QL_INTERCEPT.ENTER)
    ql.os.set_api('puts', my_puts_onexit, QL_INTERCEPT.EXIT)
    ql.run()
