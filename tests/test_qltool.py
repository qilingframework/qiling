#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import sys, subprocess, unittest
sys.path.append("..")
from qiling import *
from qiling.exception import *

class QltoolTest(unittest.TestCase):
    def testexec(self):
        create = [sys.executable, '../qltool', 'run', '-f', '../examples/rootfs/x86_reactos/bin/x86_hello.exe', '--rootfs', '../examples/rootfs/x86_reactos']
        try:
            subprocess.check_output(create,stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:    
            raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))   

    def testshellcode(self):
        create = [sys.executable, '../qltool', 'shellcode', '--os','linux','--arch', 'x86','--asm', '-f', '../examples/shellcodes/lin32_execve.asm']
        try:
            subprocess.check_output(create,stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:    
            raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))    

if __name__ == "__main__":
    unittest.main()