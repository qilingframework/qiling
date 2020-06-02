#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from binascii import unhexlify

import sys, unittest
sys.path.insert(0, "..")

from qiling import *
from qiling.exception import *

X86_WIN = unhexlify(
    'fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d6a01eb2668318b6f87ffd5bbf0b5a25668a695bd9dffd53c067c0a80fbe07505bb4713726f6a0053ffd5e8d5ffffff63616c6300'
)

X8664_WIN = unhexlify(
    'fc4881e4f0ffffffe8d0000000415141505251564831d265488b52603e488b52183e488b52203e488b72503e480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed5241513e488b52203e8b423c4801d03e8b80880000004885c0746f4801d0503e8b48183e448b40204901d0e35c48ffc93e418b34884801d64d31c94831c0ac41c1c90d4101c138e075f13e4c034c24084539d175d6583e448b40244901d0663e418b0c483e448b401c4901d03e418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a3e488b12e949ffffff5d49c7c1000000003e488d95fe0000003e4c8d850f0100004831c941ba45835607ffd54831c941baf0b5a256ffd548656c6c6f2c2066726f6d204d534621004d657373616765426f7800'
)

class PEShellcodeTest(unittest.TestCase):
    def test_windowssc_x86(self):
        ql = Qiling(shellcoder=X86_WIN, archtype="x86", ostype="windows", rootfs="../examples/rootfs/x86_windows",
                    output="default")
        ql.run()
        del ql


    def test_windowssc_x64(self):
        ql = Qiling(shellcoder=X8664_WIN, archtype="x8664", ostype="windows", rootfs="../examples/rootfs/x8664_windows",
                    output="debug")
        ql.run()
        del ql


if __name__ == "__main__":
    unittest.main()
