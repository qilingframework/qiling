#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 


import sys,unittest
from binascii import unhexlify
sys.path.append("..")
from qiling import *
from qiling.exception import *

class PETest(unittest.TestCase):
    def test_shellcode_win_x86(self):
        X86_WIN = unhexlify('fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d6a01eb2668318b6f87ffd5bbf0b5a25668a695bd9dffd53c067c0a80fbe07505bb4713726f6a0053ffd5e8d5ffffff63616c6300')
        ql = Qiling(shellcoder = X86_WIN, archtype = "x86", ostype = "windows", rootfs="../examples/rootfs/x86_windows", output="debug")
        ql.run()


    def test_pe_win_x8664_hello(self):
        ql = Qiling(["../examples/rootfs/x8664_reactos/bin/x8664_hello.exe"], "../examples/rootfs/x8664_windows", output = "default")
        ql.run()


    def test_pe_win_x86_hello(self):
        ql = Qiling(["../examples/rootfs/x86_reactos/bin/x86_hello.exe"], "../examples/rootfs/x86_windows", output = "debug")
        ql.run()


    def test_pe_win_x86_multithread(self):
        ql = Qiling(["../examples/rootfs/x86_windows/bin/MultiThread.exe"], "../examples/rootfs/x86_windows")
        ql.run()


    def test_pe_win_x86_regdemo(self):
        ql = Qiling(["../examples/rootfs/x86_windows/bin/RegDemo.exe"], "../examples/rootfs/x86_windows")
        ql.reg_dir = "registry"
        ql.reg_diff = "reg_diff.json"
        ql.run()


    def test_pe_win_x86_wannacry(self):
        def stopatkillerswtich(ql):
            print("killerswtch found")
            ql.uc.emu_stop()

        ql = Qiling(["../examples/rootfs/x86_windows/bin/wannacry.bin"], "../examples/rootfs/x86_windows", output = "debug")    
        ql.hook_address(stopatkillerswtich, 0x40819a)    
        ql.run


if __name__ == "__main__":
    unittest.main()