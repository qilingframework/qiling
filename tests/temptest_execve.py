import platform, sys, unittest, subprocess, string, random, os

from unicorn import UcError, UC_ERR_READ_UNMAPPED, UC_ERR_FETCH_UNMAPPED

sys.path.append("..")
from qiling import *
from qiling.const import *
from qiling.exception import *
from qiling.os.posix import syscall
from qiling.os.mapper import QlFsMappedObject
from qiling.os.posix.stat import Fstat
from qiling.os.filestruct import ql_file

def test_elf_linux_execve_x8664(self):
    if platform.system() == "Darwin" and platform.machine() == "arm64":
        return
    
    ql = Qiling(["../examples/rootfs/x8664_linux/bin/posix_syscall_execve"],  "../examples/rootfs/x8664_linux", verbose=QL_VERBOSE.DEBUG)   
    ql.run()

    for key, value in ql.loader.env.items():
        QL_TEST=value

    self.assertEqual("TEST_QUERY", QL_TEST)
    self.assertEqual("child", ql.loader.argv[0])

    del QL_TEST
    del ql
