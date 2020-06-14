#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import sys, subprocess, unittest
sys.path.append("..")
from qiling import *
from qiling.exception import *


class Qltool_Test(unittest.TestCase):
    def test_qltool_exec_args(self):
        create = [sys.executable, '../qltool', 'run', '-f', '../examples/rootfs/x8664_linux/bin/x8664_args', '--rootfs', '../examples/rootfs/x8664_linux', '--args', 'test1', 'test2' ,'test3']
        try:
            subprocess.check_output(create,stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:    
            raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))   

    def test_qltool_shellcode(self):
        create = [sys.executable, '../qltool', 'shellcode', '--os','linux','--arch', 'x86','--asm', '-f', '../examples/shellcodes/lin32_execve.asm']
        try:
            subprocess.check_output(create,stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:    
            raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output)) 

    def test_qltool_coverage(self):
        create = [sys.executable, '../qltool', 'run', '-f','../examples/rootfs/x8664_efi/bin/TcgPlatformSetupPolicy','--rootfs', '../examples/rootfs/x8664_efi','--coverage-format', 'drcov', '--coverage-file', 'log_test/TcgPlatformSetupPolicy']
        try:
            subprocess.check_output(create,stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:    
            raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output)) 

if __name__ == "__main__":
    unittest.main()
