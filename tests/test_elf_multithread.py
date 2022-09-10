#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import platform, sys, unittest, os, threading, time

sys.path.append("..")
from qiling import Qiling
from qiling.const import *
from qiling.exception import *
from qiling.os.filestruct import ql_file

class ELFTest(unittest.TestCase):

    @unittest.skipIf(platform.system() == "Darwin" and platform.machine() == "arm64", 'darwin host')
    def test_elf_linux_execve_x8664(self):
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/posix_syscall_execve"],  "../examples/rootfs/x8664_linux", verbose=QL_VERBOSE.DEBUG)   
        ql.run()

        for key, value in ql.loader.env.items():
            QL_TEST=value

        self.assertEqual("TEST_QUERY", QL_TEST)
        self.assertEqual("child", ql.loader.argv[0])

        del QL_TEST
        del ql


    def test_elf_linux_cloexec_x8664(self):
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/x8664_cloexec_test"],  
                    "../examples/rootfs/x8664_linux", 
                    verbose=QL_VERBOSE.DEBUG,
                    multithread=True)

        filename = 'output.txt'
        err = ql_file.open(filename, os.O_RDWR | os.O_CREAT, 0o777)

        ql.os.stderr = err
        ql.run()
        err.close()

        with open(filename, 'rb') as f:
            content = f.read()

        # cleanup
        os.remove(filename)

        self.assertIn(b'fail', content)

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
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
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
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
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
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/x8664_multithreading"], "../examples/rootfs/x8664_linux", multithread=True)
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertTrue("thread 2 ret val is" in buf_out)

        del ql


    def test_multithread_elf_linux_mips32eb(self):
        def check_write(ql, write_fd, write_buf, write_count, *args, **kw):
            nonlocal buf_out
            try:
                buf = ql.mem.read(write_buf, write_count)
                buf = buf.decode()
                buf_out = buf
            except:
                pass
        buf_out = None
        ql = Qiling(["../examples/rootfs/mips32_linux/bin/mips32_multithreading"], "../examples/rootfs/mips32_linux", multithread=True, verbose=QL_VERBOSE.DEBUG)
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
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
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
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
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertTrue("thread 2 ret val is" in buf_out)

        del ql


    def test_multithread_elf_linux_armeb(self):
        def check_write(ql, write_fd, write_buf, write_count, *args, **kw):
            nonlocal buf_out
            try:
                buf = ql.mem.read(write_buf, write_count)
                buf = buf.decode()
                buf_out = buf
            except:
                pass
        buf_out = None
        ql = Qiling(["../examples/rootfs/armeb_linux/bin/armeb_multithreading"], "../examples/rootfs/armeb_linux", multithread=True, verbose=QL_VERBOSE.DEBUG)
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
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
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
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
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
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
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
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
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertEqual("server send() 14 return 14.\n", ql.buf_out)

        del ql


    def test_tcp_elf_linux_armeb(self):
        def check_write(ql, write_fd, write_buf, write_count, *args, **kw):
            try:
                buf = ql.mem.read(write_buf, write_count)
                buf = buf.decode()
                if buf.startswith("server send()"):
                    ql.buf_out = buf
            except:
                pass
        ql = Qiling(["../examples/rootfs/armeb_linux/bin/armeb_tcp_test","20003"], "../examples/rootfs/armeb_linux", multithread=True)
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertEqual("server send() 14 return 14.\n", ql.buf_out)

        del ql


    def test_tcp_elf_linux_mips32eb(self):
        ql = Qiling(["../examples/rootfs/mips32_linux/bin/mips32_tcp_test","20005"], "../examples/rootfs/mips32_linux", multithread=True)
        ql.run()
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
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
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
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
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
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertEqual("server sendto() 14 return 14.\n", ql.buf_out)

        del ql

    def test_udp_elf_linux_armeb(self):
        def check_write(ql, write_fd, write_buf, write_count, *args, **kw):
            try:
                buf = ql.mem.read(write_buf, write_count)
                buf = buf.decode()
                if buf.startswith("server sendto()"):
                    ql.buf_out = buf
            except:
                pass

        ql = Qiling(["../examples/rootfs/armeb_linux/bin/armeb_udp_test","20010"], "../examples/rootfs/armeb_linux", multithread=True)
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertEqual("server sendto() 14 return 14.\n", ql.buf_out)

        del ql

    def test_http_elf_linux_x8664(self):
        def picohttpd():
            ql = Qiling(["../examples/rootfs/x8664_linux/bin/picohttpd","12911"], "../examples/rootfs/x8664_linux", multithread=True, verbose=QL_VERBOSE.DEBUG)    
            ql.run()


        picohttpd_therad = threading.Thread(target=picohttpd, daemon=True)
        picohttpd_therad.start()

        time.sleep(1)

        f = os.popen("curl http://127.0.0.1:12911")
        self.assertEqual("httpd_test_successful", f.read())

    def test_http_elf_linux_arm(self):
        def picohttpd():
            ql = Qiling(["../examples/rootfs/arm_linux/bin/picohttpd","12912"], "../examples/rootfs/arm_linux", multithread=True, verbose=QL_VERBOSE.DEBUG)    
            ql.run()


        picohttpd_therad = threading.Thread(target=picohttpd, daemon=True)
        picohttpd_therad.start()

        time.sleep(1)

        f = os.popen("curl http://127.0.0.1:12912")
        self.assertEqual("httpd_test_successful", f.read())

    def test_http_elf_linux_armeb(self):
        def picohttpd():
            ql = Qiling(["../examples/rootfs/armeb_linux/bin/picohttpd"], "../examples/rootfs/armeb_linux", multithread=True, verbose=QL_VERBOSE.DEBUG)    
            ql.run()


        picohttpd_thread = threading.Thread(target=picohttpd, daemon=True)
        picohttpd_thread.start()

        time.sleep(1)

        f = os.popen("curl http://127.0.0.1:12913")
        self.assertEqual("httpd_test_successful", f.read())


if __name__ == "__main__":
    unittest.main()





