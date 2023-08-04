#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import unittest

import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_INTERCEPT, QL_VERBOSE


# test = bytes.fromhex('cccc')

X86_LIN = bytes.fromhex('31c050682f2f7368682f62696e89e3505389e1b00bcd80')
X8664_LIN = bytes.fromhex('31c048bbd19d9691d08c97ff48f7db53545f995257545eb03b0f05')

MIPS32EL_LIN = bytes.fromhex('''
    ffff0628ffffd004ffff05280110e4270ff08424ab0f02240c0101012f62696e
    2f7368
''')

X86_WIN = bytes.fromhex('''
    fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c
    617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b5920
    01d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475
    e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ff
    e05f5f5a8b12eb8d5d6a01eb2668318b6f87ffd5bbf0b5a25668a695bd9dffd5
    3c067c0a80fbe07505bb4713726f6a0053ffd5e8d5ffffff63616c6300
''')

X8664_WIN = bytes.fromhex('''
    fc4881e4f0ffffffe8d0000000415141505251564831d265488b52603e488b52
    183e488b52203e488b72503e480fb74a4a4d31c94831c0ac3c617c022c2041c1
    c90d4101c1e2ed5241513e488b52203e8b423c4801d03e8b80880000004885c0
    746f4801d0503e8b48183e448b40204901d0e35c48ffc93e418b34884801d64d
    31c94831c0ac41c1c90d4101c138e075f13e4c034c24084539d175d6583e448b
    40244901d0663e418b0c483e448b401c4901d03e418b04884801d0415841585e
    595a41584159415a4883ec204152ffe05841595a3e488b12e949ffffff5d49c7
    c1000000003e488d95fe0000003e4c8d850f0100004831c941ba45835607ffd5
    4831c941baf0b5a256ffd548656c6c6f2c2066726f6d204d534621004d657373
    616765426f7800
''')

ARM_LIN = bytes.fromhex('''
    01308fe213ff2fe178460e300190491a921a0827c251033701df2f62696e2f2f
    7368
''')

ARM_THUMB = bytes.fromhex('401c01464fea011200bf')

ARM64_LIN = bytes.fromhex('''
    420002ca210080d2400080d2c81880d2010000d4e60300aa01020010020280d2
    681980d2010000d4410080d2420002cae00306aa080380d2010000d4210400f1
    65ffff54e0000010420002ca210001caa81b80d2010000d4020004d27f000001
    2f62696e2f736800
''')

X8664_FBSD = bytes.fromhex('''
    6a61586a025f6a015e990f054897baff02aaaa80f2ff524889e699046680c210
    0f05046a0f05041e4831f6990f0548976a035852488d7424f080c2100f0548b8
    523243427730637257488d3e48af74084831c048ffc00f055f4889d04889fe48
    ffceb05a0f0575f799043b48bb2f62696e2f2f73685253545f5257545e0f05
''')

X8664_MACOS = bytes.fromhex('''
    4831f65648bf2f2f62696e2f7368574889e74831d24831c0b00248c1c828b03b
    0f05
''')


# some shellcodes call execve, which under normal circumstences, does not return.
# however, those shellcodes attempt to run a non-exsting '/bin/sh' binary and do
# not bother to handle failures gracefully.
#
# the execution then continues to the next bytes, which are usually the '/bin/sh'
# string and not valid code. that causes Qiling to raise an exception, and this is
# why we need a way to thwart those execve failures and end the emulation gracefully
def graceful_execve(ql: Qiling, pathname: int, argv: int, envp: int, retval: int):
    assert retval != 0, f'execve is not expected to return on success'

    vpath = ql.os.utils.read_cstring(pathname)

    ql.log.debug(f'failed to call execve("{vpath}"), ending emulation gracefully')
    ql.stop()


class TestShellcode(unittest.TestCase):
    def test_linux_x86(self):
        print("Linux X86 32bit Shellcode")
        ql = Qiling(code=X86_LIN, archtype=QL_ARCH.X86, ostype=QL_OS.LINUX, verbose=QL_VERBOSE.OFF)
        ql.run()

    def test_linux_x64(self):
        print("Linux X86 64bit Shellcode")
        ql = Qiling(code=X8664_LIN, archtype=QL_ARCH.X8664, ostype=QL_OS.LINUX, verbose=QL_VERBOSE.OFF)
        ql.run()

    def test_linux_mips32(self):
        print("Linux MIPS 32bit EL Shellcode")
        ql = Qiling(code=MIPS32EL_LIN, archtype=QL_ARCH.MIPS, ostype=QL_OS.LINUX, verbose=QL_VERBOSE.OFF)

        ql.os.set_syscall('execve', graceful_execve, QL_INTERCEPT.EXIT)
        ql.run()

    # This shellcode needs to be changed to something non-blocking
    def test_linux_arm(self):
        print("Linux ARM 32bit Shellcode")
        ql = Qiling(code=ARM_LIN, archtype=QL_ARCH.ARM, ostype=QL_OS.LINUX, verbose=QL_VERBOSE.OFF)
        ql.run()

    def test_linux_arm_thumb(self):
        print("Linux ARM Thumb Shllcode")
        ql = Qiling(code=ARM_THUMB, archtype=QL_ARCH.ARM, ostype=QL_OS.LINUX, verbose=QL_VERBOSE.OFF, thumb=True)
        ql.run()

    def test_linux_arm64(self):
        print("Linux ARM 64bit Shellcode")
        ql = Qiling(code=ARM64_LIN, archtype=QL_ARCH.ARM64, ostype=QL_OS.LINUX, verbose=QL_VERBOSE.OFF)

        ql.os.set_syscall('execve', graceful_execve, QL_INTERCEPT.EXIT)
        ql.run()

    # #This shellcode needs to be changed to something simpler not requiring rootfs
    # def test_windows_x86(self):
    #     print("Windows X86 32bit Shellcode")
    #     ql = Qiling(code=X86_WIN, archtype=QL_ARCH.X86, ostype=QL_OS.WINDOWS, rootfs="../examples/rootfs/x86_reactos", verbose=QL_VERBOSE.OFF)
    #     ql.run()

    # #This shellcode needs to be changed to something simpler not requiring rootfs
    # def test_windows_x64(self):
    #    print("\nWindows X8664 64bit Shellcode")
    #    ql = Qiling(code=X8664_WIN, archtype=QL_ARCH.X8664, ostype=QL_OS.WINDOWS, rootfs="../examples/rootfs/x86_reactos", verbose=QL_VERBOSE.OFF)
    #    ql.run()

    # #This shellcode needs to be changed to something simpler, listen is blocking
    # def test_freebsd_x64(self):
    #    print("FreeBSD X86 64bit Shellcode")
    #    ql = Qiling(code=X8664_FBSD, archtype=QL_ARCH.X8664, ostype=QL_OS.FREEBSD, verbose=QL_VERBOSE.OFF)
    #    ql.run()

    # def test_macos_x64(self):
    #     print("macos X86 64bit Shellcode")
    #     ql = Qiling(code=X8664_macos, archtype=QL_ARCH.X8664, ostype=QL_OS.MACOS, verbose=QL_VERBOSE.OFF)
    #     ql.run()

    # def test_invalid_output(self):
    #     print("Testing Invalid output")
    #     self.assertRaises(QlErrorOutput, Qiling, code=test, archtype=QL_ARCH.ARM, ostype=QL_OS.LINUX, verbose=QL_VERBOSE.DEFAULT)


if __name__ == "__main__":
    unittest.main()
