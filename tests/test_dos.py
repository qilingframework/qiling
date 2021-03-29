#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys, unittest
sys.path.append('..')

from qiling import Qiling
from qiling.const import QL_INTERCEPT, QL_VERBOSE

class Checklist:
    def __init__(self) -> None:
        self.visited_onenter = False
        self.visited_onexit = False

class DOSTest(unittest.TestCase):

    def test_dos_8086_hello(self):
        ql = Qiling(["../examples/rootfs/8086/dos/HI.DOS_COM"], "../examples/rootfs/8086/dos", verbose=QL_VERBOSE.DEBUG)
        ck = Checklist()

        def onenter(ql: Qiling):
            ck.visited_onenter = True

        def onexit(ql: Qiling):
            ck.visited_onexit = True

        ql.set_api((0x21, 0x09), onexit, QL_INTERCEPT.EXIT)
        ql.set_api((0x21, 0x4c), onenter, QL_INTERCEPT.ENTER)

        ql.run()

        self.assertTrue(ck.visited_onenter)
        self.assertTrue(ck.visited_onexit)

if __name__ == "__main__":
    unittest.main()
