#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys

sys.path.append("..")
from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_ENDIAN, QL_VERBOSE

# MIPS64 n64 shellcode: write(1, "MIPS64 hello\n", 13) then exit_group(0).
#
# it uses the n64 syscall numbers (write=5001, exit_group=5205) and computes the
# address of the message with a bal/daddiu pc-relative trick. assembled with
# binutils mips64-linux-gnuabi64-as:
#
#         .set noreorder
#     __start:
#         li     $v0, 5001              # __NR_write
#         li     $a0, 1                 # fd = stdout
#         bal    load
#         nop
#     load:
#         daddiu $a1, $ra, (msg - load) # a1 = &msg
#         li     $a2, 13                # len
#         syscall
#         li     $v0, 5205              # __NR_exit_group
#         li     $a0, 0
#         syscall
#     msg:
#         .ascii "MIPS64 hello\n"
MIPS64EB_LIN = bytes.fromhex('''
    2402138924040001041100010000000067e500182406000d0000000c24021455
    240400000000000c4d49505336342068656c6c6f0a
''')

# little-endian counterpart of MIPS64EB_LIN: the instruction words are
# byte-swapped while the trailing string is left as-is
MIPS64EL_LIN = bytes.fromhex('''
    891302240100042401001104000000001800e5670d0006240c00000055140224
    000004240c0000004d49505336342068656c6c6f0a
''')


if __name__ == "__main__":
    print("\nLinux MIPS 64bit EB (big-endian) Shellcode")
    ql = Qiling(code=MIPS64EB_LIN, archtype=QL_ARCH.MIPS64, ostype=QL_OS.LINUX, endian=QL_ENDIAN.EB, verbose=QL_VERBOSE.DEFAULT)
    ql.run()

    print("\nLinux MIPS 64bit EL (little-endian) Shellcode")
    ql = Qiling(code=MIPS64EL_LIN, archtype=QL_ARCH.MIPS64, ostype=QL_OS.LINUX, endian=QL_ENDIAN.EL, verbose=QL_VERBOSE.DEFAULT)
    ql.run()
