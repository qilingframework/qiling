#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#
import sys
sys.path.append("..")

from qiling import Qiling
from qiling.os.const import STRING
from qiling.const import QL_VERBOSE

def my_puts(ql: Qiling):
    params = ql.os.resolve_fcall_params({'s': STRING})

    print(f'puts("{params["s"]}")')

if __name__ == "__main__":
    ql = Qiling(["rootfs/x8664_linux/bin/x8664_hello"], "rootfs/x8664_linux", verbose=QL_VERBOSE.DEBUG)
    ql.set_api('puts', my_puts)
    ql.run()
