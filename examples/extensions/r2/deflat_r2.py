#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys

sys.path.append('..')

from qiling.const import QL_VERBOSE
from qiling.extensions.r2 import R2Qiling as Qiling



if __name__ == "__main__":
    # a program obfuscated by OLLVM control flow graph flatten, which should print 4 when argv[1] is 1
    # see source code at examples/src/linux/fla_test.c
    ql = Qiling(['rootfs/x86_linux/bin/test_fla_argv', '1'], 'rootfs/x86_linux', verbose=QL_VERBOSE.DEFAULT)
    ctx = ql.save()
    r2 = ql.r2
    # now we can use r2 parsed symbol name instead of address to get function
    fcn = r2.get_fcn('target_function')
    # de-flatten the target function, ql code will be patched
    r2.deflat(fcn)
    # run the de-flattened program, it should print 4 as expected
    ql.run()
    # get a r2-like interactive shell to reverse engineering target_function
    r2.shell('target_function')
    # run `pdf` in r2 shell to print disassembly of target_function
    # we should see many patched NOP instructions

    print('restore the original program')
    ql.restore(ctx)
    r2 = ql.r2
    # the program is still obfuscated
    r2.shell('target_function')