#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys, unittest

sys.path.append("..")
from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions import pipe


def good_bad_count(test_str: str, good_str="GOOD", bad_str="BAD"):
    good_count = test_str.count(good_str)
    bad_count = test_str.count(bad_str)

    return good_count, bad_count


class CppTests_x86(unittest.TestCase):

    def test_cpp_helloworld(self):
        """ Test a basic C++ Hello World program which prints "Hello World!"
        to the console using std::cout.
        """
        ql = Qiling(["../examples/rootfs/x86_windows/bin/except/CppHelloWorld_x86.exe"], "../examples/rootfs/x86_windows/", verbose=QL_VERBOSE.DEFAULT)

        ql.os.stdout = pipe.SimpleStringBuffer()

        ql.run()

        conout = ql.os.stdout.read()
        self.assertEqual(conout, b"Hello World!\x0d\x0a")

        del ql

    def test_cpp_types(self):
        """ This program tests several C++ type-related runtime features.
        - typeid
        - dynamic_cast
        - virtual methods
        - virtual destructors
        """
        ql = Qiling(["../examples/rootfs/x86_windows/bin/except/TestCppTypes_x86.exe"], "../examples/rootfs/x86_windows/", verbose=QL_VERBOSE.DEFAULT)

        ql.os.stdout = pipe.SimpleStringBuffer()

        ql.run()

        conout = ql.os.stdout.read().decode('utf-8')
        good_count, bad_count = good_bad_count(conout)

        # the test program should print
        # - 'GOOD' 12 times
        # - 'BAD' 0 times
        self.assertEqual(good_count, 12)
        self.assertEqual(bad_count, 0)

        del ql


if __name__ == '__main__':
    unittest.main()