#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import unittest
import sys

sys.path.insert(0, "..")

from qiling.os.posix.filestruct import ql_file


class PosixTest(unittest.TestCase):
    def test_posix_qlfile(self):
        try:
            ql = ql_file.open(__file__, 0, 0xffffffff)
            ql.close()
        except OverflowError:
            self.fail('OverflowError occurred')

if __name__ == "__main__":
    unittest.main()
