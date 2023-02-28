#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os, sys, unittest

sys.path.append("..")
from qiling import Qiling
from qiling.const import QL_INTERCEPT, QL_VERBOSE
from qiling.os.const import STRING
from qiling.os.linux.fncc import linux_kernel_api

IS_FAST_TEST = 'QL_FAST_TEST' in os.environ

class ELF_KO_Test(unittest.TestCase):

    @unittest.skipIf(IS_FAST_TEST, 'fast test')
    def test_demigod_m0hamed_x86(self):
        checklist = []

        @linux_kernel_api(params={
            "format": STRING
        })
        def __my_printk(ql: Qiling, address: int, params):
            ql.log.info(f'my printk: {params=}')

            checklist.append(params['format'])

            return 0

        ql = Qiling(["../examples/rootfs/x86_linux/kernel/m0hamed_rootkit.ko"],  "../examples/rootfs/x86_linux", verbose=QL_VERBOSE.DEBUG)
        ql.os.set_api("printk", __my_printk)

        ba = ql.loader.load_address
        ql.run(ba + 0x01e0, ba + 0x01fa)

        self.assertEqual("DONT YOU EVER TRY TO READ THIS FILE OR I AM GOING TO DESTROY YOUR MOST SECRET DREAMS", checklist.pop(0))
        self.assertEqual(len(checklist), 0)

    def test_demigod_hello_x8664(self):
        checklist = []

        def __onenter_printk(ql: Qiling, address: int, params):
            ql.log.info(f'about to enter printk: {params=}')

            checklist.append(params['format'])

        ql = Qiling(["../examples/rootfs/x8664_linux/kernel/hello.ko"],  "../examples/rootfs/x8664_linux", verbose=QL_VERBOSE.DEBUG)
        ql.os.set_api("printk", __onenter_printk, QL_INTERCEPT.ENTER)

        ba = ql.loader.load_address
        ql.run(ba + 0x64, ba + 0x7e)    # run lkm_example_init
        ql.run(ba + 0x7f, ba + 0x90)    # run lkm_example_exit

        self.assertIn('Hello', checklist.pop(0))
        self.assertIn('Goodbye', checklist.pop(0))
        self.assertEqual(len(checklist), 0)

    def test_demigod_hello_mips32(self):
        checklist = []

        def __onexit_printk(ql: Qiling, address: int, params, retval: int):
            ql.log.info(f'done with printk: {params=}')

            checklist.append(params['format'])

        ql = Qiling(["../examples/rootfs/mips32_linux/kernel/hello.ko"],  "../examples/rootfs/mips32_linux", verbose=QL_VERBOSE.DEBUG)
        ql.os.set_api("printk", __onexit_printk, QL_INTERCEPT.EXIT)

        ba = ql.loader.load_address
        ql.run(ba + 0x60, ba + 0x84)    # run hello
        ql.run(ba + 0x88, ba + 0x98)    # run goodbye

        self.assertIn('Hello', checklist.pop(0))
        self.assertEqual(len(checklist), 0)


if __name__ == "__main__":
    unittest.main()
