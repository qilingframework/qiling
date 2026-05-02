#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import unittest

import sys
sys.path.append("..")

from qiling.core import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
from qiling.os.const import STRING, POINTER, SIZE_T


class BlobTest(unittest.TestCase):
    def test_uboot_arm(self):
        def my_getenv(ql: Qiling):
            env = {
                "ID": b"000000000000000",
                "ethaddr": b"11:22:33:44:55:66"
            }

            params = ql.os.resolve_fcall_params({'key': STRING})
            value = env.get(params["key"], b"")

            value_addr = ql.os.heap.alloc(len(value))
            ql.mem.write(value_addr, value)

            ql.arch.regs.r0 = value_addr
            ql.arch.regs.arch_pc = ql.arch.regs.lr

        def check_password(ql: Qiling):
            params = ql.os.resolve_fcall_params({
                'ptr1': POINTER,  # points to real password
                'ptr2': POINTER,  # points to user provided password
                'size': SIZE_T    # comparison length
            })

            ptr1 = params['ptr1']
            ptr2 = params['ptr2']
            size = params['size']

            real_password = ql.mem.read(ptr1, size)
            user_password = ql.mem.read(ptr2, size)

            self.assertSequenceEqual(real_password, user_password, seq_type=bytearray)

        def partial_run_init(ql: Qiling):
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

        ql = Qiling(code=uboot_code[0x40:], archtype=QL_ARCH.ARM, ostype=QL_OS.BLOB, profile="profiles/uboot_bin.ql", verbose=QL_VERBOSE.DEBUG)

        imgbase = ql.loader.images[0].base

        ql.hook_address(my_getenv, imgbase + 0x13AC0)
        ql.hook_address(check_password, imgbase + 0x48634)

        partial_run_init(ql)

        ql.run(imgbase + 0x486B4, imgbase + 0x48718)

        del ql

    def test_blob_raw(self):
        def run_checksum_emu(input_data_buffer: bytes) -> int:
            """
            Callable function that takes input data buffer and returns the checksum.
            """
            BASE_ADDRESS = 0x10000000
            CHECKSUM_FUNC_ADDR = BASE_ADDRESS + 0x8
            END_ADDRESS = 0x100000ba
            DATA_ADDR = 0xa0000000
            STACK_ADDR = 0xb0000000

            with open("../examples/rootfs/blob/example_raw.bin", "rb") as f:
                raw_code = f.read()

            ql = Qiling(code=raw_code, archtype=QL_ARCH.ARM, ostype=QL_OS.BLOB, profile="profiles/blob_raw.ql", verbose=QL_VERBOSE.DEBUG, thumb=True)

            input_data_len = len(input_data_buffer)

            # Map memory for data and stack
            ql.mem.map(STACK_ADDR, 0x2000)
            ql.mem.map(DATA_ADDR, ql.mem.align_up(input_data_len + 0x100))

            # Write input data
            ql.mem.write(DATA_ADDR, input_data_buffer)

            # Set up registers
            ql.arch.regs.sp = STACK_ADDR + 0x2000 - 4
            ql.arch.regs.r0 = DATA_ADDR
            ql.arch.regs.r1 = input_data_len
            ql.arch.regs.pc = CHECKSUM_FUNC_ADDR
            ql.arch.regs.lr = 0xbebebebe

            ql.run(begin=CHECKSUM_FUNC_ADDR, end=END_ADDRESS)
            result = ql.arch.regs.r0

            return result

        def calculate_expected_checksum(input_data_buffer: bytes) -> int:
            """
            Python implementation of the expected checksum calculation.
            """
            input_data_len = len(input_data_buffer)
            expected_checksum = 0

            if input_data_len >= 1 and input_data_buffer[0] == 0xDE:  # MAGIC_VALUE_1
                for i in range(min(input_data_len, 4)):
                    expected_checksum += input_data_buffer[i]
                expected_checksum += 0x10
            elif input_data_len >= 2 and input_data_buffer[1] == 0xAD:  # MAGIC_VALUE_2
                for i in range(input_data_len):
                    expected_checksum ^= input_data_buffer[i]
                expected_checksum += 0x20
            else:
                for i in range(input_data_len):
                    expected_checksum += input_data_buffer[i]

            return expected_checksum & 0xFF

        test_input = b"\x01\x02\x03\x04\x05"
        self.assertEqual(run_checksum_emu(test_input), calculate_expected_checksum(test_input))


if __name__ == "__main__":
    unittest.main()
