#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys, unittest

sys.path.append("..")
from qiling import *
from qiling.exception import *
from qiling.const import QL_VERBOSE
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
        def my_puts_onenter(ql: Qiling):
            params = ql.os.resolve_fcall_params({'s': STRING})

            print(f'puts("{params["s"]}")')
            return QL_CALL_BLOCK

        def my_puts_onexit(ql: Qiling):
            print(f'after puts')
            return QL_CALL_BLOCK

        def my_printf_onenter(ql: Qiling):
            params = ql.os.resolve_fcall_params({'s': STRING})

            print(f'printf("{params["s"]}")')
            return QL_CALL_BLOCK

        def my_printf_onexit(ql: Qiling):
            print(f'after printf')
            return QL_CALL_BLOCK

        ql = Qiling(["../examples/rootfs/arm_qnx/bin/hello_sqrt"], "../examples/rootfs/arm_qnx", verbose=QL_VERBOSE.DEBUG)
        ql.set_api('puts', my_puts_onenter, QL_INTERCEPT.ENTER)
        ql.set_api('printf', my_printf_onenter, QL_INTERCEPT.ENTER)
        
        ql.set_api('puts', my_puts_onexit, QL_INTERCEPT.EXIT)
        ql.set_api('printf', my_printf_onexit, QL_INTERCEPT.EXIT)

        ql.run()

if __name__ == "__main__":
    unittest.main()
