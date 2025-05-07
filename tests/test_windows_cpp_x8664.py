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


class CppTests_x8664(unittest.TestCase):

    def test_cpp_helloworld(self):
        """ Test a basic C++ Hello World program which prints "Hello World!"
        to the console using std::cout.
        """
        ql = Qiling(["../examples/rootfs/x8664_windows/bin/except/CppHelloWorld.exe"], "../examples/rootfs/x8664_windows/", verbose=QL_VERBOSE.DEFAULT)

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
        ql = Qiling(["../examples/rootfs/x8664_windows/bin/except/TestCppTypes.exe"], "../examples/rootfs/x8664_windows/", verbose=QL_VERBOSE.DEFAULT)

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

    def test_soft_seh(self):
        """ Test software SEH.
        This test program uses __try..__catch and calls RaiseException with
        a custom code. If software SEH is functioning correctly, the program
        should be able to invoke its __catch-block and continue execution after.
        """
        ql = Qiling(["../examples/rootfs/x8664_windows/bin/except/TestSoftSEH.exe"], "../examples/rootfs/x8664_windows/", verbose=QL_VERBOSE.DEFAULT)

        ql.os.stdout = pipe.SimpleStringBuffer()

        ql.run()

        conout = ql.os.stdout.read().decode('utf-8')
        good_count, bad_count = good_bad_count(conout)

        # the test program should print
        # - 'GOOD' 4 times
        # - 'BAD' 0 times
        self.assertEqual(good_count, 4)
        self.assertEqual(bad_count, 0)

        # If the exception handler was not invoked for some reason,
        # the program may terminate abnormally with a non-zero exit
        # code.
        self.assertEqual(ql.os.exit_code, 0)

        del ql

    def test_soft_cppex(self):
        """ Test software C++ exceptions.
        This test program tests try..catch in various ways. If exception dispatching
        and stack unwinding are functioning correctly, the program will run to completion.
        - Simple try..catch
        - Try..catch with throw data
        - Nested try..catch with throw data
        """
        ql = Qiling(["../examples/rootfs/x8664_windows/bin/except/TestCppEx.exe"], "../examples/rootfs/x8664_windows/", verbose=QL_VERBOSE.DEFAULT)

        ql.os.stdout = pipe.SimpleStringBuffer()

        ql.run()

        conout = ql.os.stdout.read().decode('utf-8')
        good_count, bad_count = good_bad_count(conout, 'y', 'n')

        # the test program should print
        # - 'y' 14 times
        # - 'n' 0 times
        self.assertEqual(good_count, 14)
        self.assertEqual(bad_count, 0)

        # If the exception handler was not invoked for some reason,
        # the program may terminate abnormally with a non-zero exit
        # code.
        self.assertEqual(ql.os.exit_code, 0)

        del ql

    def test_cppex_unhandled_filtered(self):
        """ Test unhandled C++ exceptions.
        This program registers its own unhandled exception filter via
        SetUnhandledExceptionFilter, then throws an uncaught exception.
        If unhandled exception filters are functioning correctly,
        the program's custom exception filter will be reached, but
        execution will NOT resume after the exception.
        Instead, the program is expected to terminate abnormally
        with status code 0xE06D7363 (C++ runtime exception).
        """
        ql = Qiling(["../examples/rootfs/x8664_windows/bin/except/TestCppExUnhandled.exe"], "../examples/rootfs/x8664_windows/", verbose=QL_VERBOSE.DEFAULT)

        ql.os.stdout = pipe.SimpleStringBuffer()

        ql.run()

        conout = ql.os.stdout.read().decode('utf-8')
        good_count, bad_count = good_bad_count(conout)

        # the test program should print
        # - 'GOOD' 3 times
        # - 'BAD' 0 times
        self.assertEqual(good_count, 3)
        self.assertEqual(bad_count, 0)

        # The program should have terminated abnormally
        # with status code 0xE06D7363 (C++ runtime exception).
        self.assertEqual(ql.os.exit_code, 0xE06D7363)

        del ql

    def test_cppex_unhandled_unfiltered(self):
        """ Test unhandled C++ exceptions.
        This program throws an uncaught C++ exception.
        The program is expected to terminate abnormally
        with status code 0xC0000409 (STATUS_STACK_BUFFER_OVERRUN).
        """
        ql = Qiling(["../examples/rootfs/x8664_windows/bin/except/TestCppExUnhandled2.exe"], "../examples/rootfs/x8664_windows/", verbose=QL_VERBOSE.DEFAULT)

        ql.os.stdout = pipe.SimpleStringBuffer()

        ql.run()

        conout = ql.os.stdout.read().decode('utf-8')
        good_count, bad_count = good_bad_count(conout)

        # the test program should print
        # - 'GOOD' 1 time
        # - 'BAD' 0 times
        self.assertEqual(good_count, 1)
        self.assertEqual(bad_count, 0)

        # The program is expected to terminate abnormally
        # with status code 0xC0000409 (STATUS_STACK_BUFFER_OVERRUN)
        # https://devblogs.microsoft.com/oldnewthing/20190108-00/?p=100655
        #
        self.assertEqual(ql.os.exit_code, 0xC0000409)

        del ql

if __name__ == '__main__':
    unittest.main()