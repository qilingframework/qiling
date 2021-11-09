#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys, unittest
sys.path.append("..")

from qiling.core import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions.pipe import SimpleOutStream

class RISCVTest(unittest.TestCase):
    def test_riscv32_hello_linux(self):
        stdout = SimpleOutStream(1)
        ql = Qiling(['../examples/rootfs/riscv32_linux/bin/hello'], '../examples/rootfs/riscv32_linux/', 
                    verbose=QL_VERBOSE.DEBUG, stdout=stdout)


        ql.run()
        self.assertTrue(stdout.read() == b'Hello, World!\n')

    def test_riscv64_hello_linux(self):
        stdout = SimpleOutStream(1)
        ql = Qiling(['../examples/rootfs/riscv64_linux/bin/hello'], '../examples/rootfs/riscv64_linux/', 
                    verbose=QL_VERBOSE.DEBUG, stdout=stdout)


        ql.run()
        self.assertTrue(stdout.read() == b'Hello, World!\n')

if __name__ == "__main__":
    unittest.main()