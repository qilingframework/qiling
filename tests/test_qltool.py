#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import sys, subprocess
sys.path.append("..")
from qiling import *
from qiling.exception import *


def testexec_args():
    create = [sys.executable, '../qltool', 'run', '-f', '../examples/rootfs/x8664_linux/bin/x8664_args', '--rootfs', '../examples/rootfs/x8664_linux', '--args', 'test1', 'test2' ,'test3']
    try:
        subprocess.check_output(create,stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:    
        raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))   

def testshellcode():
    create = [sys.executable, '../qltool', 'shellcode', '--os','linux','--arch', 'x86','--asm', '-f', '../examples/shellcodes/lin32_execve.asm']
    try:
        subprocess.check_output(create,stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:    
        raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))    

def teststrace_filter():
    create = ["../qltool", "run", "-f", "../examples/rootfs/mips32el_linux/bin/mips32el_hello", "--rootfs", "../examples/rootfs/mips32el_linux", "--strace", "-e", "brk"]
    try:
        subprocess.check_output(create, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.retruncode, e.output))

if __name__ == "__main__":
    testexec_args()
    testshellcode()
    teststrace_filter()
