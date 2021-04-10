#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys, subprocess, unittest

sys.path.append("..")
from qiling import *
from qiling.exception import *

import os

class Qltool_Test(unittest.TestCase):
    def test_qltool_exec_args(self):
        create = [sys.executable, '../qltool', 'run', '-f', '../examples/rootfs/x8664_linux/bin/x8664_args', '--rootfs', '../examples/rootfs/x8664_linux', '--verbose', '0', '--args', 'test1', 'test2' ,'test3']
        p = subprocess.Popen(create, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in iter(p.stdout.readline, b''):
            self.stdout = line
	
        self.assertEqual(b'arg        2 test3\n', self.stdout)
		

    def test_qltool_shellcode(self):
        create = [sys.executable, '../qltool', 'code', '--os','linux','--arch', 'x86','--asm', '-f', '../examples/shellcodes/lin32_execve.asm']
        try:
            subprocess.check_output(create,stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:    
            raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output)) 

    def test_qltool_coverage(self):
        os.makedirs("./log_test", exist_ok=True)
        create = [sys.executable, '../qltool', 'run', '-f','../examples/rootfs/x8664_efi/bin/TcgPlatformSetupPolicy','--rootfs', '../examples/rootfs/x8664_efi','--coverage-format', 'drcov', '--coverage-file', 'log_test/TcgPlatformSetupPolicy']
        try:
            subprocess.check_output(create, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:    
            raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output)) 

    def test_qltool_json(self):
        create = [sys.executable, '../qltool', 'run', '-f','../examples/rootfs/x86_linux/bin/x86_hello','--rootfs', '../examples/rootfs/x86_linux','--verbose', '0', '--json']
        try:
            subprocess.check_output(create, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))

    def test_qltool_filter(self):
        create = [sys.executable, '../qltool', 'run', '-f', '../examples/rootfs/arm_linux/bin/arm_hello', '--rootfs', '../examples/rootfs/arm_linux', '-e', '^(open|brk)', '--log-plain']
        try:
            output = subprocess.check_output(create, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))

        lines = [ line.strip('[=]\t') for line in output.decode().split("\n")]
        self.assertTrue(all(filter(lambda x: x.startswith("open") or x.startswith("brk"), lines)))


if __name__ == "__main__":
    unittest.main()
