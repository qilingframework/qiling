#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys, unittest

sys.path.append("..")
from qiling import *
from qiling.exception import *
from qiling.const import QL_VERBOSE


class QNXTest(unittest.TestCase):
    def test_arm_qnx(self):
        env = {"FOO": "bar"}
        ql = Qiling(
            ["../examples/rootfs/arm_qnx/bin/hello", "foo", "bar"],
            "../examples/rootfs/arm_qnx",
            env=env,
            verbose=QL_VERBOSE.DEBUG,
        )
        ql.run()


if __name__ == "__main__":
    unittest.main()
