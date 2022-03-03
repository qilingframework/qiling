#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os, sys, unittest

from unicorn import UcError

sys.path.append("..")
from qiling import Qiling
from qiling.const import QL_INTERCEPT, QL_VERBOSE
from qiling.os.const import STRING
from qiling.os.linux.fncc import linux_kernel_api

IS_FAST_TEST = 'QL_FAST_TEST' in os.environ

class ELF_KO_Test(unittest.TestCase):

    def test_demigod_m0hamed_x86(self):
        if IS_FAST_TEST:
            self.skipTest('QL_FAST_TEST')

        checklist = {}

        @linux_kernel_api(params={
            "format": STRING
        })
        def my_printk(ql: Qiling, address: int, params):
            ql.log.info(f'oncall printk: params = {params}')

            checklist['oncall'] = params['format']

            return 0

        ql = Qiling(["../examples/rootfs/x86_linux/kernel/m0hamed_rootkit.ko"],  "../examples/rootfs/x86_linux", verbose=QL_VERBOSE.DEBUG)
        ql.os.set_api("printk", my_printk)

        ba = ql.loader.load_address

        try:
            ql.run(ba + 0x11e0, ba + 0x11fa)
        except UcError as e:
            self.fail(e)
        else:
            self.assertEqual("DONT YOU EVER TRY TO READ THIS FILE OR I AM GOING TO DESTROY YOUR MOST SECRET DREAMS", checklist['oncall'])

    def test_demigod_hello_x8664(self):
        checklist = {}

        def my_onenter(ql: Qiling, address: int, params):
            ql.log.info(f'onenter printk: params = {params}')

            checklist['onenter'] = params['format']

        ql = Qiling(["../examples/rootfs/x8664_linux/kernel/hello.ko"],  "../examples/rootfs/x8664_linux", verbose=QL_VERBOSE.DEBUG)
        ql.os.set_api("printk", my_onenter, QL_INTERCEPT.ENTER)

        ba = ql.loader.load_address
        ql.run(ba + 0x1064, ba + 0x107e)

        self.assertEqual("\x016Hello, World: %p!\n", checklist['onenter'])

    def test_demigod_hello_mips32(self):
        checklist = {}

        def my_onexit(ql: Qiling, address: int, params, retval: int):
            ql.log.info(f'onexit printk: params = {params}')

            checklist['onexit'] = params['format']

        ql = Qiling(["../examples/rootfs/mips32_linux/kernel/hello.ko"],  "../examples/rootfs/mips32_linux", verbose=QL_VERBOSE.DEBUG)
        ql.os.set_api("printk", my_onexit, QL_INTERCEPT.EXIT)

        ba = ql.loader.load_address
        ql.run(ba + 0x1060, ba + 0x1084)

        self.assertEqual("\x016Hello, World!\n", checklist['onexit'])

if __name__ == "__main__":
    unittest.main()
