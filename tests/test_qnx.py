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
    # def test_arm_qnx_static(self):
    #     env = {
    #         "FOO": "bar"
    #     }
    #     ql = Qiling(["../examples/rootfs/arm_qnx/bin/hello_static", "foo", "bar"], "../examples/rootfs/arm_qnx", env=env, verbose=QL_VERBOSE.DEBUG)
    #     ql.run()

    # def test_arm_qnx_sqrt(self):
    #     ql = Qiling(["../examples/rootfs/arm_qnx/bin/hello_sqrt"], "../examples/rootfs/arm_qnx", verbose=QL_VERBOSE.DEBUG)
    #     ql.run()
    
    def test_set_api_arm_qnx_sqrt(self):
        def my_msg_sendv(ql: Qiling):
            # params = ql.os.resolve_fcall_params({'s': STRING})
            # print(f'puts("{params["s"]}")')
            print("Set API_DONE")

        ql = Qiling(["../examples/rootfs/arm_qnx/bin/hello_sqrt"], "../examples/rootfs/arm_qnx", verbose=QL_VERBOSE.DEBUG)
        ql.set_api('msg_sendv', my_msg_sendv)
        ql.run()

if __name__ == "__main__":
    unittest.main()
