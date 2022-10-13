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
    ql = R2Qiling(['rootfs/x86_linux/bin/test_fla_argv', '1'], 'rootfs/x86_linux', verbose=QL_VERBOSE.DEFAULT)
    r2 = ql.r2
    # now r2 has only rbuf but no symbol info
    fcn = r2.get_fcn_at(0x08049190)
    print(fcn)
    r2.deflat(fcn)
    ql.run()
    r2.shell()
