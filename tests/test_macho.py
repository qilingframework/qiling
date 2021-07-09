#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys, unittest

sys.path.append("..")

from qiling import *
from qiling.exception import *
from qiling.const import QL_VERBOSE


class MACHOTest(unittest.TestCase):
    def test_macho_macos_x8664(self):
        ql = Qiling(
            ["../examples/rootfs/x8664_macos/bin/x8664_hello"],
            "../examples/rootfs/x8664_macos",
            verbose=QL_VERBOSE.DEBUG,
        )
        ql.run()

    def test_usercorn_x8664(self):
        ql = Qiling(
            ["../examples/rootfs/x8664_macos/bin/x8664_hello_usercorn"],
            "../examples/rootfs/x8664_macos",
            verbose=QL_VERBOSE.DEBUG,
        )
        ql.run()


if __name__ == "__main__":
    unittest.main()
