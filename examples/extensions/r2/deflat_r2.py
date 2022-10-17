#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys

sys.path.append('..')

from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions.r2 import R2Qiling



if __name__ == "__main__":
    # a program obfuscated by OLLVM CFF flatten, which should print 4 when argv[1] is 1
    # see source code at examples/src/linux/fla_test.c
    ql = R2Qiling(['rootfs/x86_linux/bin/test_fla_argv', '1'], 'rootfs/x86_linux', verbose=QL_VERBOSE.DEFAULT)
    r2 = ql.r2
    # now we can use r2 parsed symbol name instead of address
    fcn = r2.get_fcn_at(r2.where('target_function'))
    print(fcn)
    r2.deflat(fcn)
    ql.run()
    r2.shell()
