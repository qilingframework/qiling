#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys, unittest

sys.path.append("..")
from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions import pipe

class RustTests_x8664(unittest.TestCase):

    def test_rust_helloworld(self):
        """This tests the default Rust Hello World program
        compiled on 64-bit Windows.
        """
        ql = Qiling(["../examples/rootfs/x8664_windows/bin/x8664_rust_helloworld.exe"], "../examples/rootfs/x8664_windows/", verbose=QL_VERBOSE.DEFAULT)

        ql.os.stdout = pipe.SimpleStringBuffer()
        
        ql.run()

        conout = ql.os.stdout.read().decode('utf-8')

        # The program's output will contain the "Hello, world!"
        # string if there were no errors.
        self.assertIn("Hello, world!", conout)

        del ql

if __name__ == '__main__':
    unittest.main()