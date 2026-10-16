#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys, unittest

sys.path.append("..")
from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions import pipe

class TlsTests_x8664(unittest.TestCase):

    def test_tls_multithread(self):
        """The program used in this test uses TlsAlloc to 
        allocate a new TLS slot, and then spawns multiple threads using
        CreateThread.

        Each thread calls TlsSetValue and TlsGetValue using the allocated
        TLS slot.

        The program waits on all threads using WaitForMultipleObjects,
        and then calls TlsFree before exiting.

        Success of the test depends on a reasonably correct implementation
        of TLS, as well as correct behavior of CreateThread
        and thread waiting.
        """
        ql = Qiling(["../examples/rootfs/x8664_windows/bin/x8664_tls_multithread.exe"], "../examples/rootfs/x8664_windows/", verbose=QL_VERBOSE.DEFAULT)

        ql.os.stdout = pipe.SimpleStringBuffer()
        
        ql.run()

        # The program is expected to return 0 on success
        self.assertEqual(ql.os.exit_code, 0)

        conout = ql.os.stdout.read().decode('utf-8')

        # The program's output will contain SUCCESS
        # if there were no errors.
        self.assertIn("SUCCESS", conout)

        # The program will print lines containing
        # FAIL if there are errors.
        self.assertNotIn("FAIL", conout)

        del ql

if __name__ == '__main__':
    unittest.main()