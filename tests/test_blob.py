#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys, unittest
sys.path.append("..")

from qiling.core import Qiling
from qiling.const import QL_VERBOSE
from qiling.os.const import STRING

class BlobTest(unittest.TestCase):
    def test_uboot_arm(self):
        def my_getenv(ql, *args, **kwargs):
            env = {"ID": b"000000000000000", "ethaddr": b"11:22:33:44:55:66"}
            params = ql.os.resolve_fcall_params({'key': STRING})
            value = env.get(params["key"], b"")

            value_addr = ql.os.heap.alloc(len(value))
            ql.mem.write(value_addr, value)

            ql.arch.regs.r0 = value_addr
            ql.arch.regs.arch_pc = ql.arch.regs.lr

        def check_password(ql, *args, **kwargs):
            passwd_output = ql.mem.read(ql.arch.regs.r0, ql.arch.regs.r2)
            passwd_input = ql.mem.read(ql.arch.regs.r1, ql.arch.regs.r2)
            self.assertEqual(passwd_output, passwd_input)

        def partial_run_init(ql):
            # argv prepare
            ql.arch.regs.arch_sp -= 0x30
            arg0_ptr = ql.arch.regs.arch_sp
            ql.mem.write(arg0_ptr, b"kaimendaji")

            ql.arch.regs.arch_sp -= 0x10
            arg1_ptr = ql.arch.regs.arch_sp
            ql.mem.write(arg1_ptr, b"013f1f")

            ql.arch.regs.arch_sp -= 0x20
            argv_ptr = ql.arch.regs.arch_sp
            ql.mem.write_ptr(argv_ptr, arg0_ptr)
            ql.mem.write_ptr(argv_ptr + ql.arch.pointersize, arg1_ptr)

            ql.arch.regs.r2 = 2
            ql.arch.regs.r3 = argv_ptr

        print("ARM uboot bin")

        with open("../examples/rootfs/blob/u-boot.bin.img", "rb") as f:
            uboot_code = f.read()

        ql = Qiling(code=uboot_code[0x40:], archtype="arm", ostype="blob", profile="profiles/uboot_bin.ql", verbose=QL_VERBOSE.DEBUG)

        image_base_addr = ql.loader.load_address
        ql.hook_address(my_getenv, image_base_addr + 0x13AC0)
        ql.hook_address(check_password, image_base_addr + 0x48634)

        partial_run_init(ql)

        ql.run(image_base_addr + 0x486B4, image_base_addr + 0x48718)

        del ql


if __name__ == "__main__":
    unittest.main()
