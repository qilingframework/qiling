#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("..")

from qiling.core import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
from qiling.os.const import STRING


def get_kaimendaji_password():
    def my_getenv(ql: Qiling):
        env = {
            "ID"      : b"000000000000000",
            "ethaddr" : b"11:22:33:44:55:66"
        }

        params = ql.os.resolve_fcall_params({'key': STRING})
        value = env.get(params["key"], b"")

        value_addr = ql.os.heap.alloc(len(value))
        ql.mem.write(value_addr, value)

        ql.arch.regs.r0 = value_addr
        ql.arch.regs.arch_pc = ql.arch.regs.lr

    def get_password(ql: Qiling):
        password_raw = ql.mem.read(ql.arch.regs.r0, ql.arch.regs.r2)

        password = ''
        for item in password_raw:
            if 0 <= item <= 9:
                password += chr(item + 48)
            else:
                password += chr(item + 87)

        print("The password is: %s" % password)

    def partial_run_init(ql: Qiling):
        # argv prepare
        ql.arch.regs.arch_sp -= 0x30
        arg0_ptr = ql.arch.regs.arch_sp
        ql.mem.write(arg0_ptr, b"kaimendaji")

        ql.arch.regs.arch_sp -= 0x10
        arg1_ptr = ql.arch.regs.arch_sp
        ql.mem.write(arg1_ptr, b"000000")   # arbitrary password

        ql.arch.regs.arch_sp -= 0x20
        argv_ptr = ql.arch.regs.arch_sp
        ql.mem.write_ptr(argv_ptr, arg0_ptr)
        ql.mem.write_ptr(argv_ptr + ql.arch.pointersize, arg1_ptr)

        ql.arch.regs.r2 = 2
        ql.arch.regs.r3 = argv_ptr

    with open("../examples/rootfs/blob/u-boot.bin.img", "rb") as f:
        uboot_code = f.read()

    ql = Qiling(code=uboot_code[0x40:], archtype=QL_ARCH.ARM, ostype=QL_OS.BLOB, profile="uboot_bin.ql", verbose=QL_VERBOSE.OFF)

    image_base_addr = ql.loader.load_address
    ql.hook_address(my_getenv, image_base_addr + 0x13AC0)
    ql.hook_address(get_password, image_base_addr + 0x48634)

    partial_run_init(ql)

    ql.run(image_base_addr + 0x486B4, image_base_addr + 0x48718)


if __name__ == "__main__":
    get_kaimendaji_password()
