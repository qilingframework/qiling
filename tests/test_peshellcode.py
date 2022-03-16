#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys, unittest

sys.path.append("..")
from qiling import Qiling

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

POINTER_TEST = bytes.fromhex('1122334455667788')

class PEShellcodeTest(unittest.TestCase):
    def test_windowssc_x86(self):
        ql = Qiling(code=X86_WIN, archtype="x86", ostype="windows", rootfs="../examples/rootfs/x86_windows")
        ql.run()
        del ql


    def test_windowssc_x64(self):
        ql = Qiling(code=X8664_WIN, archtype="x8664", ostype="windows", rootfs="../examples/rootfs/x8664_windows")
        ql.run()
        del ql

    def test_read_ptr32(self):
        ql = Qiling(code=POINTER_TEST, archtype="x86", ostype="windows", rootfs="../examples/rootfs/x86_windows")

        addr = ql.loader.entry_point
        self.assertEqual(0x11, ql.mem.read_ptr(addr, 1))
        self.assertEqual(0x2211, ql.mem.read_ptr(addr, 2))
        self.assertEqual(0x44332211, ql.mem.read_ptr(addr, 4))
        self.assertEqual(0x44332211, ql.mem.read_ptr(addr))
        self.assertEqual(0x8877665544332211, ql.mem.read_ptr(addr, 8))
        del ql

    def test_read_ptr64(self):
        ql = Qiling(code=POINTER_TEST, archtype="x8664", ostype="windows", rootfs="../examples/rootfs/x8664_windows")

        addr = ql.loader.entry_point
        self.assertEqual(0x11, ql.mem.read_ptr(addr, 1))
        self.assertEqual(0x2211, ql.mem.read_ptr(addr, 2))
        self.assertEqual(0x44332211, ql.mem.read_ptr(addr, 4))
        self.assertEqual(0x8877665544332211, ql.mem.read_ptr(addr, 8))
        self.assertEqual(0x8877665544332211, ql.mem.read_ptr(addr))
        del ql


if __name__ == "__main__":
    unittest.main()
