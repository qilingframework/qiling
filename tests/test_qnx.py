#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import unittest

import sys
sys.path.append("..")

from qiling import Qiling
from qiling.exception import *
from qiling.const import QL_INTERCEPT, QL_CALL_BLOCK, QL_VERBOSE
from qiling.os.const import STRING


class QNXTest(unittest.TestCase):

    def test_arm_qnx_static(self):
        env = {
            "FOO": "bar"
        }
        ql = Qiling(["../examples/rootfs/arm_qnx/bin/hello_static", "foo", "bar"], "../examples/rootfs/arm_qnx", env=env, verbose=QL_VERBOSE.DEBUG)
        ql.run()

    def test_arm_qnx_sqrt(self):
        ql = Qiling(["../examples/rootfs/arm_qnx/bin/hello_sqrt"], "../examples/rootfs/arm_qnx", verbose=QL_VERBOSE.DEBUG)
        ql.run()

    def test_set_api_arm_qnx_sqrt(self):
        self.set_api_puts_onenter = False
        self.set_api_puts_onexit = False
        self.set_api_printf_onenter = False
        self.set_api_printf_onexit = False

        def my_puts_onenter(ql: Qiling):
            params = ql.os.resolve_fcall_params({'s': STRING})

            print(f'puts("{params["s"]}")')
            self.set_api_puts_onenter = True
            return QL_CALL_BLOCK

        def my_puts_onexit(ql: Qiling):
            print(f'after puts')
            self.set_api_puts_onexit = True
            return QL_CALL_BLOCK

        def my_printf_onenter(ql: Qiling):
            params = ql.os.resolve_fcall_params({'s': STRING})

            print(f'printf("{params["s"]}")')
            self.set_api_printf_onenter = True
            return QL_CALL_BLOCK

        def my_printf_onexit(ql: Qiling):
            print(f'after printf')
            self.set_api_printf_onexit = True
            return QL_CALL_BLOCK

        ql = Qiling(["../examples/rootfs/arm_qnx/bin/hello_sqrt"], "../examples/rootfs/arm_qnx", verbose=QL_VERBOSE.DEBUG)
        ql.os.set_api('puts', my_puts_onenter, QL_INTERCEPT.ENTER)
        ql.os.set_api('printf', my_printf_onenter, QL_INTERCEPT.ENTER)

        # ql.os.set_api('puts', my_puts_onexit, QL_INTERCEPT.EXIT)
        ql.os.set_api('printf', my_printf_onexit, QL_INTERCEPT.EXIT)

        ql.run()

        self.assertEqual(False, self.set_api_puts_onenter)
        self.assertEqual(False, self.set_api_puts_onexit)
        self.assertEqual(True, self.set_api_printf_onenter)
        self.assertEqual(True, self.set_api_printf_onexit)

        del self.set_api_puts_onenter
        del self.set_api_puts_onexit
        del self.set_api_printf_onenter
        del self.set_api_printf_onexit


if __name__ == "__main__":
    unittest.main()
