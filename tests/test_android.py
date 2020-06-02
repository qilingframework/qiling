#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import unittest
import os
import sys
sys.path.append("..")

from qiling import *
from qiling.const import *
from qiling.os.posix.syscall.unistd import ql_syscall_pread64

# syscalls that need to be implemented for android
def syscall_getrandom(ql, buf, buflen, flags, *args, **kw):
    data = None
    regreturn = None
    try:
        data = os.urandom(buflen)
        ql.uc.mem_write(buf, data)
        regreturn = len(data)
    except:
        regreturn = -1

    ql.nprint("getrandom(0x%x, 0x%x, 0x%x) = %d" %
              (buf, buflen, flags, regreturn))

    if data:
        ql.dprint(D_CTNT, "[+] getrandom() CONTENT:")
        ql.dprint(D_CTNT, str(data))
    ql.os.definesyscall_return(regreturn)


"""
Android linker calls fstatfs to determine if the file is on tmpfs as part of checking if libraries are allowed
https://cs.android.com/android/platform/superproject/+/master:bionic/linker/linker.cpp;l=1215
"""
def syscall_fstatfs(ql, fd, buf, *args, **kw):
    data = b"0" * (12*8)  # for now, just return 0s
    regreturn = None
    try:
        ql.uc.mem_write(buf, data)
        regreturn = 0
    except:
        regreturn = -1

    ql.nprint("fstatfs(0x%x, 0x%x) = %d" % (fd, buf, regreturn))

    if data:
        ql.dprint(0, "[+] fstatfs() CONTENT:")
        ql.dprint(0, str(data))
    ql.os.definesyscall_return(regreturn)


class TestAndroid(unittest.TestCase):
    def test_android_arm64(self):
        test_binary = "../examples/rootfs/arm64_android/bin/arm64_android_hello"
        rootfs = "../examples/rootfs/arm64_android"

        # FUTURE FIX: at this stage, need a file called /proc/self/exe in the rootfs - Android linker calls stat against /proc/self/exe and bails if it can't find it
        # qiling handles readlink against /proc/self/exe, but doesn't handle it in stat
        # https://cs.android.com/android/platform/superproject/+/master:bionic/linker/linker_main.cpp;l=221
        self.assertTrue(os.path.isfile(os.path.join(rootfs, "proc", "self", "exe")), rootfs +
                        "/proc/self/exe not found, Android linker will bail. Need a file at that location (empty is fine)")

        ql = Qiling([test_binary], rootfs, output="debug")

        # slide in the syscalls we need for android on arm64
        # FUTURE FIX: implement fstatfs
        ql.set_syscall(0x2C, syscall_fstatfs)
        # FUTURE FIX: pread64 implemented in qiling, just not hooked up for arm64
        ql.set_syscall(0x43, ql_syscall_pread64)
        # FUTURE FIX: implement getrandom
        ql.set_syscall(0x116, syscall_getrandom)

        ql.run()


if __name__ == "__main__":
    unittest.main()
