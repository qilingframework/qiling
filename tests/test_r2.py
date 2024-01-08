#!/usr/bin/env python3

import unittest
from io import StringIO

import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_ARCH, QL_INTERCEPT, QL_OS, QL_VERBOSE
from tests.test_shellcode import ARM64_LIN, graceful_execve

try:
    from qiling.extensions.r2.r2 import R2
except ImportError:
    test_r2 = False
else:
    test_r2 = True

@unittest.skipUnless(test_r2, 'libr is missing')
class R2Test(unittest.TestCase):
    def test_addr_flag(self):
        ql = Qiling(["../examples/rootfs/x86_windows/bin/x86_hello.exe"], "../examples/rootfs/x86_windows",
                    verbose=QL_VERBOSE.DISABLED)  # x8864_hello does not have 'main'
        r2 = R2(ql)
        print(r2.where('main'))
        self.assertEqual(r2.at(r2.where('main')), 'main')

    def test_disasm_monkeypatch(self):
        # QlArchUtils.setup_output(QL_VERBOSE.DISASM) implicitly uses r2.disassembler if available
        # see https://github.com/qilingframework/qiling/issues/1396
        ql = Qiling(code=ARM64_LIN, archtype=QL_ARCH.ARM64, ostype=QL_OS.LINUX, verbose=QL_VERBOSE.DISASM)
        ql.os.set_syscall('execve', graceful_execve, QL_INTERCEPT.EXIT)

        # store ql log output in a string
        ql_log = StringIO()
        ql.log.handlers[0].setStream(ql_log)
        ql.run()

        ql_log_str = ql_log.getvalue()
        self.assertFalse('invalid' in ql_log_str)
        self.assertTrue('adr                  x1, #0x11ff058' in ql_log_str)

if __name__ == "__main__":
    unittest.main()
