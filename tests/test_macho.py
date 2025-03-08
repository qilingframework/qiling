#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import unittest

import sys

sys.path.append("..")

from qiling import Qiling
from qiling.arch.models import X86_CPU_MODEL
from qiling.const import QL_VERBOSE


ROOTFS = r'../examples/rootfs/x8664_macos'


class MACHOTest(unittest.TestCase):
    def test_macho_macos_x8664(self):
        ql = Qiling([fr'{ROOTFS}/bin/x8664_hello'], ROOTFS, cputype=X86_CPU_MODEL.INTEL_HASWELL, verbose=QL_VERBOSE.DEBUG)
        ql.run()

    def test_usercorn_x8664(self):
        ql = Qiling([fr'{ROOTFS}/bin/x8664_hello_usercorn'], ROOTFS, cputype=X86_CPU_MODEL.INTEL_HASWELL, verbose=QL_VERBOSE.DEBUG)
        ql.run()


if __name__ == "__main__":
    unittest.main()
