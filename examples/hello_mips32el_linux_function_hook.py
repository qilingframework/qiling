#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_INTERCEPT, QL_CALL_BLOCK, QL_VERBOSE
from qiling.os.const import STRING

def my_puts_onenter(ql: Qiling):
    params = ql.os.resolve_fcall_params({'s': STRING})

    print(f'puts("{params["s"]}")')
    return QL_CALL_BLOCK

def my_puts_onexit(ql: Qiling):
    print(f'after puts')
    return QL_CALL_BLOCK

if __name__ == "__main__":
    ql = Qiling(["rootfs/mips32el_linux/bin/mips32el_double_hello"], "rootfs/mips32el_linux", verbose=QL_VERBOSE.DEBUG)

    ql.set_api('puts', my_puts_onenter, QL_INTERCEPT.ENTER)
    ql.set_api('puts', my_puts_onexit, QL_INTERCEPT.EXIT)

    ql.run()
