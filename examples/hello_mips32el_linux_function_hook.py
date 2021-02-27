#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys

sys.path.append("..")
from qiling import Qiling
from qiling.os.const import STRING
from qiling.const import QL_INTERCEPT

def my_puts_onenter(ql: Qiling):
    params = ql.os.resolve_fcall_params({'s': STRING})

    print(f'puts("{params["s"]}")')
    return 2

def my_puts_onexit(ql: Qiling):
    print(f'after puts')
    return 2

if __name__ == "__main__":
    ql = Qiling(["rootfs/mips32el_linux/bin/mips32el_double_hello"], "rootfs/mips32el_linux", output="debug")

    ql.set_api('puts', my_puts_onenter, QL_INTERCEPT.ENTER)
    ql.set_api('puts', my_puts_onexit, QL_INTERCEPT.EXIT)

    ql.run()