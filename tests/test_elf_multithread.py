#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys, unittest, subprocess, string, random, os

from unicorn import UcError, UC_ERR_READ_UNMAPPED, UC_ERR_FETCH_UNMAPPED

sys.path.append("..")
from qiling import *
from qiling.const import *
from qiling.exception import *
from qiling.os.posix import syscall
from qiling.os.mapper import QlFsMappedObject
from qiling.os.posix.stat import Fstat

class ELFTest(unittest.TestCase):

    def test_elf_linux_execve_x8664(self):
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/posix_syscall_execve"],  "../examples/rootfs/x8664_linux", verbose=QL_VERBOSE.DEBUG)
        ql.run()
        for key, value in ql.loader.env.items():
            QL_TEST=value

        self.assertEqual("TEST_QUERY", QL_TEST)
        self.assertEqual("child", ql.loader.argv[0])

        del QL_TEST
        del ql


    def test_multithread_elf_linux_x86(self):
        def check_write(ql, write_fd, write_buf, write_count, *args, **kw):
            nonlocal buf_out
            try:
                buf = ql.mem.read(write_buf, write_count)
                buf = buf.decode()
                buf_out = buf
            except:
                pass
        buf_out = None
        ql = Qiling(["../examples/rootfs/x86_linux/bin/x86_multithreading"], "../examples/rootfs/x86_linux", multithread=True, verbose=QL_VERBOSE.DEBUG)
        ql.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertTrue("thread 2 ret val is" in buf_out)

        del ql


    def test_multithread_elf_linux_arm64(self):
        def check_write(ql, write_fd, write_buf, write_count, *args, **kw):
            nonlocal buf_out
            try:
                buf = ql.mem.read(write_buf, write_count)
                buf = buf.decode()
                buf_out = buf
            except:
                pass
        buf_out = None
        ql = Qiling(["../examples/rootfs/arm64_linux/bin/arm64_multithreading"], "../examples/rootfs/arm64_linux", multithread=True, verbose=QL_VERBOSE.DEBUG)
        ql.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertTrue("thread 2 ret val is" in buf_out)

        del ql


    def test_multithread_elf_linux_x8664(self):
        def check_write(ql, write_fd, write_buf, write_count, *args, **kw):
            nonlocal buf_out
            try:
                buf = ql.mem.read(write_buf, write_count)
                buf = buf.decode()
                buf_out = buf
            except:
                pass
        buf_out = None
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/x8664_multithreading"], "../examples/rootfs/x8664_linux", multithread=True, profile= "profiles/append_test.ql")
        ql.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertTrue("thread 2 ret val is" in buf_out)

        del ql


    def test_multithread_elf_linux_mips32el(self):
        def check_write(ql, write_fd, write_buf, write_count, *args, **kw):
            nonlocal buf_out
            try:
                buf = ql.mem.read(write_buf, write_count)
                buf = buf.decode()
                buf_out = buf
            except:
                pass
        buf_out = None
        ql = Qiling(["../examples/rootfs/mips32el_linux/bin/mips32el_multithreading"], "../examples/rootfs/mips32el_linux", multithread=True, verbose=QL_VERBOSE.DEBUG)
        ql.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertTrue("thread 2 ret val is" in buf_out)

        del ql


    def test_multithread_elf_linux_arm(self):
        def check_write(ql, write_fd, write_buf, write_count, *args, **kw):
            nonlocal buf_out
            try:
                buf = ql.mem.read(write_buf, write_count)
                buf = buf.decode()
                buf_out = buf
            except:
                pass
        buf_out = None
        ql = Qiling(["../examples/rootfs/arm_linux/bin/arm_multithreading"], "../examples/rootfs/arm_linux", multithread=True, verbose=QL_VERBOSE.DEBUG)
        ql.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertTrue("thread 2 ret val is" in buf_out)

        del ql


    def test_tcp_elf_linux_x86(self):
        def check_write(ql, write_fd, write_buf, write_count, *args, **kw):
            try:
                buf = ql.mem.read(write_buf, write_count)
                buf = buf.decode()
                if buf.startswith("server send()"):
                    ql.buf_out = buf
            except:
                pass
        ql = Qiling(["../examples/rootfs/x86_linux/bin/x86_tcp_test","20001"], "../examples/rootfs/x86_linux", multithread=True)
        ql.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertEqual("server send() 14 return 14.\n", ql.buf_out)

        del ql


    def test_tcp_elf_linux_x8664(self):
        def check_write(ql, write_fd, write_buf, write_count, *args, **kw):
            try:
                buf = ql.mem.read(write_buf, write_count)
                buf = buf.decode()
                if buf.startswith("server send()"):
                    ql.buf_out = buf
            except:
                pass
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/x8664_tcp_test","20002"], "../examples/rootfs/x8664_linux", multithread=True)
        ql.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertEqual("server send() 14 return 14.\n", ql.buf_out)

        del ql


    def test_tcp_elf_linux_arm(self):
        def check_write(ql, write_fd, write_buf, write_count, *args, **kw):
            try:
                buf = ql.mem.read(write_buf, write_count)
                buf = buf.decode()
                if buf.startswith("server write()"):
                    ql.buf_out = buf
            except:
                pass
        ql = Qiling(["../examples/rootfs/arm_linux/bin/arm_tcp_test","20003"], "../examples/rootfs/arm_linux", multithread=True)
        ql.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertEqual("server write() 14 return 14.\n", ql.buf_out)

        del ql


    def test_tcp_elf_linux_arm64(self):
        def check_write(ql, write_fd, write_buf, write_count, *args, **kw):
            try:
                buf = ql.mem.read(write_buf, write_count)
                buf = buf.decode()
                if buf.startswith("server send()"):
                    ql.buf_out = buf
            except:
                pass
        ql = Qiling(["../examples/rootfs/arm64_linux/bin/arm64_tcp_test","20004"], "../examples/rootfs/arm64_linux", multithread=True)
        ql.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertEqual("server send() 14 return 14.\n", ql.buf_out)

        del ql


    def test_tcp_elf_linux_mips32el(self):
        ql = Qiling(["../examples/rootfs/mips32el_linux/bin/mips32el_tcp_test","20005"], "../examples/rootfs/mips32el_linux", multithread=True)
        ql.run()
        del ql


    def test_udp_elf_linux_x86(self):
        def check_write(ql, write_fd, write_buf, write_count, *args, **kw):
            try:
                buf = ql.mem.read(write_buf, write_count)
                buf = buf.decode()
                if buf.startswith("server sendto()"):
                    ql.buf_out = buf
            except:
                pass

        ql = Qiling(["../examples/rootfs/x86_linux/bin/x86_udp_test","20007"], "../examples/rootfs/x86_linux", multithread=True)
        ql.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertEqual("server sendto() 14 return 14.\n", ql.buf_out)

        del ql


    def test_udp_elf_linux_x8664(self):
        def check_write(ql, write_fd, write_buf, write_count, *args, **kw):
            try:
                buf = ql.mem.read(write_buf, write_count)
                buf = buf.decode()
                if buf.startswith("server sendto()"):
                    ql.buf_out = buf
            except:
                pass

        ql = Qiling(["../examples/rootfs/x8664_linux/bin/x8664_udp_test","20008"], "../examples/rootfs/x8664_linux", multithread=True)
        ql.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertEqual("server sendto() 14 return 14.\n", ql.buf_out)

        del ql

    def test_udp_elf_linux_arm64(self):
        def check_write(ql, write_fd, write_buf, write_count, *args, **kw):
            try:
                buf = ql.mem.read(write_buf, write_count)
                buf = buf.decode()
                if buf.startswith("server sendto()"):
                    ql.buf_out = buf
            except:
                pass

        ql = Qiling(["../examples/rootfs/arm64_linux/bin/arm64_udp_test","20009"], "../examples/rootfs/arm64_linux", multithread=True)
        ql.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertEqual("server sendto() 14 return 14.\n", ql.buf_out)

        del ql

if __name__ == "__main__":
    unittest.main()


