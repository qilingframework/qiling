#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os, sys, unittest

sys.path.append("..")
from qiling import *
from qiling.const import QL_VERBOSE


class TestAndroid(unittest.TestCase):
    def test_android_arm64(self):
        test_binary = "../examples/rootfs/arm64_android/bin/arm64_android_hello"
        rootfs = "../examples/rootfs/arm64_android"

        # FUTURE FIX: at this stage, need a file called /proc/self/exe in the rootfs - Android linker calls stat against /proc/self/exe and bails if it can't find it
        # qiling handles readlink against /proc/self/exe, but doesn't handle it in stat
        # https://cs.android.com/android/platform/superproject/+/master:bionic/linker/linker_main.cpp;l=221
        self.assertTrue(
            os.path.isfile(os.path.join(rootfs, "proc", "self", "exe")),
            rootfs
            + "/proc/self/exe not found, Android linker will bail. Need a file at that location (empty is fine)",
        )

        ql = Qiling(
            [test_binary], rootfs, verbose=QL_VERBOSE.DEBUG, multithread=True
        )
        ql.run()


if __name__ == "__main__":
    unittest.main()
