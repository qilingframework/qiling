#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys, unittest, subprocess, string, random, os, logging

from unicorn import UcError, UC_ERR_READ_UNMAPPED, UC_ERR_FETCH_UNMAPPED

sys.path.append("..")
from qiling import *
from qiling.const import *
from qiling.exception import *
from qiling.os.posix import syscall
from qiling.os.mapper import QlFsMappedObject
from qiling.os.stat import Fstat

class ELF_KO_Test(unittest.TestCase):

    def test_demigod_m0hamed_x86(self):
        ql = Qiling(["../examples/rootfs/x86_linux/kernel/m0hamed_rootkit.ko"],  "../examples/rootfs/x86_linux", output="disasm")
        try:
            procfile_read_func_begin = ql.loader.load_address + 0x11e0
            procfile_read_func_end = ql.loader.load_address + 0x11fa
            ql.run(begin=procfile_read_func_begin, end=procfile_read_func_end)
        except UcError as e:
            print(e)
            sys.exit(-1)
        del ql

    def test_demigod_hello_x8664(self):
        ql = Qiling(["../examples/rootfs/x8664_linux/kernel/hello.ko"],  "../examples/rootfs/x8664_linux", output="disasm")
        try:
            procfile_read_func_begin = ql.loader.load_address + 0x1064
            procfile_read_func_end = ql.loader.load_address + 0x107e
            ql.run(begin=procfile_read_func_begin, end=procfile_read_func_end)
        except UcError as e:
            print(e)
            sys.exit(-1)
        del ql

    def test_demigod_hello_mips32(self):
        ql = Qiling(["../examples/rootfs/mips32_linux/kernel/hello.ko"],  "../examples/rootfs/mips32_linux", output="debug")
        begin = ql.loader.load_address + 0x1060
        end = ql.loader.load_address + 0x1084
        ql.run(begin=begin, end=end)
        del ql


if __name__ == "__main__":
    unittest.main()
