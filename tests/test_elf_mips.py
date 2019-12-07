#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 


import sys,unittest
sys.path.append("..")
from qiling import *
from qiling.exception import *

class ELFTest(unittest.TestCase):
    def test_elf_linux_x8664(self):
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/tester","1234test", "12345678", "bin/x8664_hello"],  "../examples/rootfs/x8664_linux", output="debug")
        ql.run()


    def test_elf_linux_x86(self):
        ql = Qiling(["../examples/rootfs/x86_linux/bin/x86_hello"], "../examples/rootfs/x86_linux", output="debug")
        ql.run()


    # Not Stable, not suitable to use it as test
    #def test_multithread_elf_linux_x86(self):
    #    ql = Qiling(["../examples/rootfs/x86_linux/bin/x86_multithreading"], "../examples/rootfs/x86_linux", output="debug")
    #    ql.run()

    def test_elf_linux_arm(self):     
        ql = Qiling(["../examples/rootfs/arm_linux/bin/arm_hello"], "../examples/rootfs/arm_linux", output = "default")
        ql.run()


    def test_elf_linux_arm64(self):     
        ql = Qiling(["../examples/rootfs/arm64_linux/bin/arm64_hello"], "../examples/rootfs/arm64_linux", output = "default")
        ql.set_exit(0x555555566260)
        ql.run()


    def test_elf_linux_mips32el(self):     
        ql = Qiling(["../examples/rootfs/mips32el_linux/bin/mips32el_hello"], "../examples/rootfs/mips32el_linux")
        ql.run()

    
    def test_elf_linux_mips32el_filename(self):     
        ql = Qiling(["elf/mipstests"], "../examples/rootfs/mips32el_linux")
        ql.run()        
        

    def test_elf_freebsd_x8664(self):     
        ql = Qiling(["../examples/rootfs/x8664_freebsd/bin/x8664_hello_asm"], "../examples/rootfs/x8664_freebsd", output = "disasm")
        ql.run()  


if __name__ == "__main__":
    unittest.main()