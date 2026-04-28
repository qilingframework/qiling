#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("..")

from qiling.core import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
from qiling.os.const import STRING, SIZE_T, POINTER


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
    # we land on a memcmp call, where the real password is being compared to
    # the one provided by the user. we can follow the arguments to read the
    # real password

    params = ql.os.resolve_fcall_params({
        'ptr1': POINTER,    # points to real password
        'ptr2': POINTER,    # points to user provided password
        'size': SIZE_T      # comparison length
        })

    ptr1 = params['ptr1']
    size = params['size']

    password_raw = ql.mem.read(ptr1, size)

    def __hex_digit(ch: int) -> str:
        off = ord('0') if ch in range(10) else ord('a') - 10

        return chr(ch + off)

    # should be: "013f1f"
    password = "".join(__hex_digit(ch) for ch in password_raw)

    print(f'The password is: {password}')


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


if __name__ == "__main__":
    with open("../examples/rootfs/blob/u-boot.bin.img", "rb") as f:
        uboot_code = f.read()

    ql = Qiling(code=uboot_code[0x40:], archtype=QL_ARCH.ARM, ostype=QL_OS.BLOB, profile="uboot_bin.ql", verbose=QL_VERBOSE.DEBUG)

    imgbase = ql.loader.images[0].base

    ql.hook_address(my_getenv, imgbase + 0x13AC0)
    ql.hook_address(get_password, imgbase + 0x48634)

    partial_run_init(ql)

    ql.run(imgbase + 0x486B4, imgbase + 0x48718)
