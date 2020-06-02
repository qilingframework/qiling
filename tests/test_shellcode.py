#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import sys,unittest
from binascii import unhexlify
sys.path.append("..")
from qiling import *
from qiling.exception import *

test = unhexlify('cccc')
X86_LIN = unhexlify('31c050682f2f7368682f62696e89e3505389e1b00bcd80')
X8664_LIN = unhexlify('31c048bbd19d9691d08c97ff48f7db53545f995257545eb03b0f05')
MIPS32EL_LIN = unhexlify('ffff0628ffffd004ffff05280110e4270ff08424ab0f02240c0101012f62696e2f7368')
X86_WIN = unhexlify('fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d6a01eb2668318b6f87ffd5bbf0b5a25668a695bd9dffd53c067c0a80fbe07505bb4713726f6a0053ffd5e8d5ffffff63616c6300')
X8664_WIN = unhexlify('fc4881e4f0ffffffe8d0000000415141505251564831d265488b52603e488b52183e488b52203e488b72503e480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed5241513e488b52203e8b423c4801d03e8b80880000004885c0746f4801d0503e8b48183e448b40204901d0e35c48ffc93e418b34884801d64d31c94831c0ac41c1c90d4101c138e075f13e4c034c24084539d175d6583e448b40244901d0663e418b0c483e448b401c4901d03e418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a3e488b12e949ffffff5d49c7c1000000003e488d95fe0000003e4c8d850f0100004831c941ba45835607ffd54831c941baf0b5a256ffd548656c6c6f2c2066726f6d204d534621004d657373616765426f7800') 
ARM_LIN = unhexlify('01108fe211ff2fe102200121921a0f02193701df061c08a11022023701df3f270221301c01df0139fbd505a0921a05b469460b2701dfc046020012340a0002022f73797374656d2f62696e2f736800')
ARM64_LIN = unhexlify('420002ca210080d2400080d2c81880d2010000d4e60300aa01020010020280d2681980d2010000d4410080d2420002cae00306aa080380d2010000d4210400f165ffff54e0000010420002ca210001caa81b80d2010000d4020004d27f0000012f62696e2f736800')
X8664_FBSD = unhexlify('6a61586a025f6a015e990f054897baff02aaaa80f2ff524889e699046680c2100f05046a0f05041e4831f6990f0548976a035852488d7424f080c2100f0548b8523243427730637257488d3e48af74084831c048ffc00f055f4889d04889fe48ffceb05a0f0575f799043b48bb2f62696e2f2f73685253545f5257545e0f05')
X8664_macos = unhexlify('4831f65648bf2f2f62696e2f7368574889e74831d24831c0b00248c1c828b03b0f05')

class TestShellcode(unittest.TestCase):
    def test_linux_x86(self):
        print("Linux X86 32bit Shellcode")
        ql = Qiling(shellcoder = X86_LIN, archtype = "x86", ostype = "linux", output = "off")
        ql.run()

    def test_linux_x64(self):
        print("Linux X86 64bit Shellcode")
        ql = Qiling(shellcoder = X8664_LIN, archtype = "x8664", ostype = "linux", output = "off")
        ql.run()

    def test_linux_mips32(self):
        print("Linux MIPS 32bit EL Shellcode")
        ql = Qiling(shellcoder = MIPS32EL_LIN, archtype = "mips", ostype = "linux", output = "off")
        ql.run()

    #This shellcode needs to be changed to something non-blocking
    #def test_linux_arm(self):
    #    print("Linux ARM 32bit Shellcode")
    #    ql = Qiling(shellcoder = ARM_LIN, archtype = "arm", ostype = "linux", output = "off")
    #    ql.run()

    
    def test_linux_arm64(self):
        print("Linux ARM 64bit Shellcode")
        ql = Qiling(shellcoder = ARM64_LIN, archtype = "arm64", ostype = "linux", output = "off")
        ql.run()

    # #This shellcode needs to be changed to something simpler not requiring rootfs
    # def test_windows_x86(self):
    #     print("Windows X86 32bit Shellcode")
    #     ql = Qiling(shellcoder = X86_WIN, archtype = "x86", ostype = "windows", rootfs="../examples/rootfs/x86_reactos", output="off")
    #     ql.run()

    # #This shellcode needs to be changed to something simpler not requiring rootfs
    # def test_windows_x64(self):
    #    print("\nWindows X8664 64bit Shellcode")
    #    ql = Qiling(shellcoder = X8664_WIN, archtype = "x8664", ostype = "windows", rootfs="../examples/rootfs/x86_reactos", output="off")
    #    ql.run()

    #This shellcode needs to be changed to something simpler, listen is blocking
    #def test_freebsd_x64(self):
    #    print("FreeBSD X86 64bit Shellcode")
    #    ql = Qiling(shellcoder = X8664_FBSD, archtype = "x8664", ostype = "freebsd", output = "off")
    #    ql.run()

    def test_macos_x64(self):
        print("macos X86 64bit Shellcode")
        ql = Qiling(shellcoder = X8664_macos, archtype = "x8664", ostype = "macos", output = "off")
        ql.run()

    def test_invalid_os(self):
        print("Testing Unknown OS")
        self.assertRaises(QlErrorOsType,  Qiling, shellcoder = test, archtype = "arm64", ostype = "qilingos", output = "default" )

    def test_invalid_arch(self):
        print("Testing Unknown Arch")
        self.assertRaises(QlErrorArch,  Qiling, shellcoder = test, archtype = "qilingarch", ostype = "linux", output = "default" )

    def test_invalid_output(self):
        print("Testing Invalid output")
        self.assertRaises(QlErrorOutput,  Qiling, shellcoder = test, archtype = "arm64", ostype = "linux", output = "blafooxyz" )
        

if __name__ == "__main__":
    unittest.main()
