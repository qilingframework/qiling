#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import http.client
import platform
import re
import sys
import os
import threading
import time
import unittest

from typing import List

sys.path.append("..")
from qiling import Qiling
from qiling.const import *
from qiling.exception import *
from qiling.os.filestruct import ql_file
from qiling.os.stats import QlOsNullStats


BASE_ROOTFS = r'../examples/rootfs'
X86_LINUX_ROOTFS = fr'{BASE_ROOTFS}/x86_linux'
X64_LINUX_ROOTFS = fr'{BASE_ROOTFS}/x8664_linux'
ARM_LINUX_ROOTFS = fr'{BASE_ROOTFS}/arm_linux'
ARMEB_LINUX_ROOTFS = fr'{BASE_ROOTFS}/armeb_linux'
ARM64_LINUX_ROOTFS = fr'{BASE_ROOTFS}/arm64_linux'
MIPSEB_LINUX_ROOTFS = fr'{BASE_ROOTFS}/mips32_linux'
MIPSEL_LINUX_ROOTFS = fr'{BASE_ROOTFS}/mips32el_linux'


class ELFTest(unittest.TestCase):

    @unittest.skipIf(platform.system() == "Darwin" and platform.machine() == "arm64", 'darwin host')
    def test_elf_linux_execve_x8664(self):
        ql = Qiling([fr'{X64_LINUX_ROOTFS}/bin/posix_syscall_execve'], X64_LINUX_ROOTFS, verbose=QL_VERBOSE.DEBUG)
        ql.run()

        env = ql.loader.env

        self.assertIn('QL_TEST', env)
        self.assertEqual('TEST_QUERY', env['QL_TEST'])
        self.assertEqual('child', ql.loader.argv[0])

    def test_elf_linux_cloexec_x8664(self):
        ql = Qiling([fr'{X64_LINUX_ROOTFS}/bin/x8664_cloexec_test'], X64_LINUX_ROOTFS, multithread=True, verbose=QL_VERBOSE.DEBUG)

        filename = 'stderr.txt'
        err = ql_file.open(filename, os.O_RDWR | os.O_CREAT, 0o644)

        ql.os.stats = QlOsNullStats()
        ql.os.stderr = err

        ql.run()
        err.close()

        with open(filename, 'r') as f:
            contents = f.readlines()

        # cleanup
        os.remove(filename)

        self.assertGreaterEqual(len(contents), 4)
        self.assertIn('Operation not permitted', contents[-2])
        self.assertIn('Operation not permitted', contents[-1])

    def test_multithread_elf_linux_x86(self):
        logged: List[str] = []

        def check_write(ql: Qiling, fd: int, write_buf, count: int):
            if fd == 1:
                content = ql.mem.read(write_buf, count)

                logged.append(content.decode())

        ql = Qiling([fr'{X86_LINUX_ROOTFS}/bin/x86_multithreading'], X86_LINUX_ROOTFS, multithread=True, verbose=QL_VERBOSE.DEBUG)

        ql.os.stats = QlOsNullStats()
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertGreaterEqual(len(logged), 2)
        self.assertTrue(logged[-2].startswith('thread 1 ret val is'))
        self.assertTrue(logged[-1].startswith('thread 2 ret val is'))

    def test_multithread_elf_linux_arm64(self):
        logged: List[str] = []

        def check_write(ql: Qiling, fd: int, write_buf, count: int):
            if fd == 1:
                content = ql.mem.read(write_buf, count)

                logged.append(content.decode())

        ql = Qiling([fr'{ARM64_LINUX_ROOTFS}/bin/arm64_multithreading'], ARM64_LINUX_ROOTFS, multithread=True, verbose=QL_VERBOSE.DEBUG)

        ql.os.stats = QlOsNullStats()
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertGreaterEqual(len(logged), 2)
        self.assertTrue(logged[-2].startswith('thread 1 ret val is'))
        self.assertTrue(logged[-1].startswith('thread 2 ret val is'))

    def test_multithread_elf_linux_x8664(self):
        logged: List[str] = []

        def check_write(ql: Qiling, fd: int, write_buf, count: int):
            if fd == 1:
                content = ql.mem.read(write_buf, count)

                logged.append(content.decode())

        ql = Qiling([fr'{X64_LINUX_ROOTFS}/bin/x8664_multithreading'], X64_LINUX_ROOTFS, multithread=True, verbose=QL_VERBOSE.DEBUG)

        ql.os.stats = QlOsNullStats()
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertGreaterEqual(len(logged), 2)
        self.assertTrue(logged[-2].startswith('thread 1 ret val is'))
        self.assertTrue(logged[-1].startswith('thread 2 ret val is'))

    def test_multithread_elf_linux_mips32eb(self):
        logged: List[str] = []

        def check_write(ql: Qiling, fd: int, write_buf, count: int):
            if fd == 1:
                content = ql.mem.read(write_buf, count)

                logged.append(content.decode())

        ql = Qiling([fr'{MIPSEB_LINUX_ROOTFS}/bin/mips32_multithreading'], MIPSEB_LINUX_ROOTFS, multithread=True, verbose=QL_VERBOSE.DEBUG)

        ql.os.stats = QlOsNullStats()
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertGreaterEqual(len(logged), 2)
        self.assertTrue(logged[-2].startswith('thread 1 ret val is'))
        self.assertTrue(logged[-1].startswith('thread 2 ret val is'))

    def test_multithread_elf_linux_mips32el(self):
        logged: List[str] = []

        def check_write(ql: Qiling, fd: int, write_buf, count: int):
            if fd == 1:
                content = ql.mem.read(write_buf, count)

                logged.append(content.decode())

        ql = Qiling([fr'{MIPSEL_LINUX_ROOTFS}/bin/mips32el_multithreading'], MIPSEL_LINUX_ROOTFS, multithread=True, verbose=QL_VERBOSE.DEBUG)

        ql.os.stats = QlOsNullStats()
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertGreaterEqual(len(logged), 2)
        self.assertTrue(logged[-2].startswith('thread 1 ret val is'))
        self.assertTrue(logged[-1].startswith('thread 2 ret val is'))

    def test_multithread_elf_linux_arm(self):
        logged: List[str] = []

        def check_write(ql: Qiling, fd: int, write_buf, count: int):
            if fd == 1:
                content = ql.mem.read(write_buf, count)

                logged.append(content.decode())

        ql = Qiling([fr'{ARM_LINUX_ROOTFS}/bin/arm_multithreading'], ARM_LINUX_ROOTFS, multithread=True, verbose=QL_VERBOSE.DEBUG)

        ql.os.stats = QlOsNullStats()
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertGreaterEqual(len(logged), 2)
        self.assertTrue(logged[-2].startswith('thread 1 ret val is'))
        self.assertTrue(logged[-1].startswith('thread 2 ret val is'))

    @unittest.skip('broken: unicorn.unicorn.UcError: Invalid instruction (UC_ERR_INSN_INVALID)')
    def test_multithread_elf_linux_armeb(self):
        logged: List[str] = []

        def check_write(ql: Qiling, fd: int, write_buf, count: int):
            if fd == 1:
                content = ql.mem.read(write_buf, count)

                logged.append(content.decode())

        ql = Qiling([fr'{ARMEB_LINUX_ROOTFS}/bin/armeb_multithreading'], ARMEB_LINUX_ROOTFS, multithread=True, verbose=QL_VERBOSE.DEBUG)

        ql.os.stats = QlOsNullStats()
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertGreaterEqual(len(logged), 2)
        self.assertTrue(logged[-2].startswith('thread 1 ret val is'))
        self.assertTrue(logged[-1].startswith('thread 2 ret val is'))

    def test_tcp_elf_linux_x86(self):
        logged: List[str] = []

        def check_write(ql: Qiling, fd: int, write_buf, count: int):
            if fd == 2:
                content = ql.mem.read(write_buf, count)

                logged.append(content.decode())

        ql = Qiling([fr'{X86_LINUX_ROOTFS}/bin/x86_tcp_test', '20000'], X86_LINUX_ROOTFS, multithread=True, verbose=QL_VERBOSE.DEBUG)

        ql.os.stats = QlOsNullStats()
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertGreaterEqual(len(logged), 2)
        self.assertTrue(logged[-2].startswith('server recv()'))
        self.assertTrue(logged[-1].startswith('server send()'))

        # the server is expected to send the value it received, for example:
        #   'server recv() return 14.\n'
        #   'server send() 14 return 14.\n'

        m = re.search(r'(?P<num>\d+)\.\s+\Z', logged[-2])
        self.assertIsNotNone(m, 'could not extract numeric value from log message')

        num = m.group('num')
        msg = logged[-1].strip()

        self.assertTrue(msg.endswith(f'{num} return {num}.'))

    def test_tcp_elf_linux_x8664(self):
        logged: List[str] = []

        def check_write(ql: Qiling, fd: int, write_buf, count: int):
            if fd == 2:
                content = ql.mem.read(write_buf, count)

                logged.append(content.decode())

        ql = Qiling([fr'{X64_LINUX_ROOTFS}/bin/x8664_tcp_test', '20001'], X64_LINUX_ROOTFS, multithread=True, verbose=QL_VERBOSE.DEBUG)

        ql.os.stats = QlOsNullStats()
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertGreaterEqual(len(logged), 2)
        self.assertTrue(logged[-2].startswith('server recv()'))
        self.assertTrue(logged[-1].startswith('server send()'))

        # the server is expected to send the value it received, for example:
        #   'server recv() return 14.\n'
        #   'server send() 14 return 14.\n'

        m = re.search(r'(?P<num>\d+)\.\s+\Z', logged[-2])
        self.assertIsNotNone(m, 'could not extract numeric value from log message')

        num = m.group('num')
        msg = logged[-1].strip()

        self.assertTrue(msg.endswith(f'{num} return {num}.'))

    def test_tcp_elf_linux_arm(self):
        logged: List[str] = []

        def check_write(ql: Qiling, fd: int, write_buf, count: int):
            if fd == 2:
                content = ql.mem.read(write_buf, count)

                logged.append(content.decode())

        ql = Qiling([fr'{ARM_LINUX_ROOTFS}/bin/arm_tcp_test', '20002'], ARM_LINUX_ROOTFS, multithread=True, verbose=QL_VERBOSE.DEBUG)

        ql.os.stats = QlOsNullStats()
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertGreaterEqual(len(logged), 2)
        self.assertTrue(logged[-2].startswith('server read()'))
        self.assertTrue(logged[-1].startswith('server write()'))

        # the server is expected to send the value it received, for example:
        #   'server read() return 14.\n'
        #   'server write() 14 return 14.\n'

        m = re.search(r'(?P<num>\d+)\.\s+\Z', logged[-2])
        self.assertIsNotNone(m, 'could not extract numeric value from log message')

        num = m.group('num')
        msg = logged[-1].strip()

        self.assertTrue(msg.endswith(f'{num} return {num}.'))

    def test_tcp_elf_linux_arm64(self):
        logged: List[str] = []

        def check_write(ql: Qiling, fd: int, write_buf, count: int):
            if fd == 2:
                content = ql.mem.read(write_buf, count)

                logged.append(content.decode())

        ql = Qiling([fr'{ARM64_LINUX_ROOTFS}/bin/arm64_tcp_test', '20003'], ARM64_LINUX_ROOTFS, multithread=True, verbose=QL_VERBOSE.DEBUG)

        ql.os.stats = QlOsNullStats()
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertGreaterEqual(len(logged), 2)
        self.assertTrue(logged[-2].startswith('server recv()'))
        self.assertTrue(logged[-1].startswith('server send()'))

        # the server is expected to send the value it received, for example:
        #   'server recv() return 14.\n'
        #   'server send() 14 return 14.\n'

        m = re.search(r'(?P<num>\d+)\.\s+\Z', logged[-2])
        self.assertIsNotNone(m, 'could not extract numeric value from log message')

        num = m.group('num')
        msg = logged[-1].strip()

        self.assertTrue(msg.endswith(f'{num} return {num}.'))

    def test_tcp_elf_linux_armeb(self):
        logged: List[str] = []

        def check_write(ql: Qiling, fd: int, write_buf, count: int):
            if fd == 2:
                content = ql.mem.read(write_buf, count)

                logged.append(content.decode())

        ql = Qiling([fr'{ARMEB_LINUX_ROOTFS}/bin/armeb_tcp_test', '20004'], ARMEB_LINUX_ROOTFS, multithread=True, verbose=QL_VERBOSE.DEBUG)

        ql.os.stats = QlOsNullStats()
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertGreaterEqual(len(logged), 2)
        self.assertTrue(logged[-2].startswith('server recv()'))
        self.assertTrue(logged[-1].startswith('server send()'))

        # the server is expected to send the value it received, for example:
        #   'server recv() return 14.\n'
        #   'server send() 14 return 14.\n'

        m = re.search(r'(?P<num>\d+)\.\s+\Z', logged[-2])
        self.assertIsNotNone(m, 'could not extract numeric value from log message')

        num = m.group('num')
        msg = logged[-1].strip()

        self.assertTrue(msg.endswith(f'{num} return {num}.'))

    def test_tcp_elf_linux_mips32eb(self):
        logged: List[str] = []

        def check_write(ql: Qiling, fd: int, write_buf, count: int):
            if fd == 2:
                content = ql.mem.read(write_buf, count)

                logged.append(content.decode())

        ql = Qiling([fr'{MIPSEB_LINUX_ROOTFS}/bin/mips32_tcp_test', '20005'], MIPSEB_LINUX_ROOTFS, multithread=True, verbose=QL_VERBOSE.DEBUG)

        ql.os.stats = QlOsNullStats()
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertGreaterEqual(len(logged), 2)
        self.assertTrue(logged[-2].startswith('server recv()'))
        self.assertTrue(logged[-1].startswith('server send()'))

        # the server is expected to send the value it received, for example:
        #   'server recv() return 14.\n'
        #   'server send() 14 return 14.\n'

        m = re.search(r'(?P<num>\d+)\.\s+\Z', logged[-2])
        self.assertIsNotNone(m, 'could not extract numeric value from log message')

        num = m.group('num')
        msg = logged[-1].strip()

        self.assertTrue(msg.endswith(f'{num} return {num}.'))

    def test_tcp_elf_linux_mips32el(self):
        logged: List[str] = []

        def check_write(ql: Qiling, fd: int, write_buf, count: int):
            if fd == 2:
                content = ql.mem.read(write_buf, count)

                logged.append(content.decode())

        ql = Qiling([fr'{MIPSEL_LINUX_ROOTFS}/bin/mips32el_tcp_test', '20006'], MIPSEL_LINUX_ROOTFS, multithread=True, verbose=QL_VERBOSE.DEBUG)

        ql.os.stats = QlOsNullStats()
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertGreaterEqual(len(logged), 2)
        self.assertTrue(logged[-2].startswith('server read()'))
        self.assertTrue(logged[-1].startswith('server write()'))

        # the server is expected to send the value it received, for example:
        #   'server read() return 14.\n'
        #   'server write() 14 return 14.\n'

        m = re.search(r'(?P<num>\d+)\.\s+\Z', logged[-2])
        self.assertIsNotNone(m, 'could not extract numeric value from log message')

        num = m.group('num')
        msg = logged[-1].strip()

        self.assertTrue(msg.endswith(f'{num} return {num}.'))

    def test_udp_elf_linux_x86(self):
        logged: List[str] = []

        def check_write(ql: Qiling, fd: int, write_buf, count: int):
            if fd == 2:
                content = ql.mem.read(write_buf, count)

                logged.append(content.decode())

        ql = Qiling([fr'{X86_LINUX_ROOTFS}/bin/x86_udp_test', '20010'], X86_LINUX_ROOTFS, multithread=True, verbose=QL_VERBOSE.DEBUG)

        ql.os.stats = QlOsNullStats()
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertGreaterEqual(len(logged), 2)
        self.assertTrue(logged[-2].startswith('server recvfrom()'))
        self.assertTrue(logged[-1].startswith('server sendto()'))

        # the server is expected to send the value it received, for example:
        #   'server recvfrom() return 14.\n'
        #   'server sendto() 14 return 14.\n'

        m = re.search(r'(?P<num>\d+)\.\s+\Z', logged[-2])
        self.assertIsNotNone(m, 'could not extract numeric value from log message')

        num = m.group('num')
        msg = logged[-1].strip()

        self.assertTrue(msg.endswith(f'{num} return {num}.'))

    def test_udp_elf_linux_x8664(self):
        logged: List[str] = []

        def check_write(ql: Qiling, fd: int, write_buf, count: int):
            if fd == 2:
                content = ql.mem.read(write_buf, count)

                logged.append(content.decode())

        ql = Qiling([fr'{X64_LINUX_ROOTFS}/bin/x8664_udp_test', '20011'], X64_LINUX_ROOTFS, multithread=True, verbose=QL_VERBOSE.DEBUG)

        ql.os.stats = QlOsNullStats()
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertGreaterEqual(len(logged), 2)
        self.assertTrue(logged[-2].startswith('server recvfrom()'))
        self.assertTrue(logged[-1].startswith('server sendto()'))

        # the server is expected to send the value it received, for example:
        #   'server recvfrom() return 14.\n'
        #   'server sendto() 14 return 14.\n'

        m = re.search(r'(?P<num>\d+)\.\s+\Z', logged[-2])
        self.assertIsNotNone(m, 'could not extract numeric value from log message')

        num = m.group('num')
        msg = logged[-1].strip()

        self.assertTrue(msg.endswith(f'{num} return {num}.'))

    def test_udp_elf_linux_arm64(self):
        logged: List[str] = []

        def check_write(ql: Qiling, fd: int, write_buf, count: int):
            if fd == 2:
                content = ql.mem.read(write_buf, count)

                logged.append(content.decode())

        ql = Qiling([fr'{ARM64_LINUX_ROOTFS}/bin/arm64_udp_test', '20013'], ARM64_LINUX_ROOTFS, multithread=True, verbose=QL_VERBOSE.DEBUG)

        ql.os.stats = QlOsNullStats()
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertGreaterEqual(len(logged), 2)
        self.assertTrue(logged[-2].startswith('server recvfrom()'))
        self.assertTrue(logged[-1].startswith('server sendto()'))

        # the server is expected to send the value it received, for example:
        #   'server recvfrom() return 14.\n'
        #   'server sendto() 14 return 14.\n'

        m = re.search(r'(?P<num>\d+)\.\s+\Z', logged[-2])
        self.assertIsNotNone(m, 'could not extract numeric value from log message')

        num = m.group('num')
        msg = logged[-1].strip()

        self.assertTrue(msg.endswith(f'{num} return {num}.'))

    def test_udp_elf_linux_armeb(self):
        logged: List[str] = []

        def check_write(ql: Qiling, fd: int, write_buf, count: int):
            if fd == 2:
                content = ql.mem.read(write_buf, count)

                logged.append(content.decode())

        ql = Qiling([fr'{ARMEB_LINUX_ROOTFS}/bin/armeb_udp_test', '20014'], ARMEB_LINUX_ROOTFS, multithread=True, verbose=QL_VERBOSE.DEBUG)

        ql.os.stats = QlOsNullStats()
        ql.os.set_syscall("write", check_write, QL_INTERCEPT.ENTER)
        ql.run()

        self.assertGreaterEqual(len(logged), 2)
        self.assertTrue(logged[-2].startswith('server recvfrom()'))
        self.assertTrue(logged[-1].startswith('server sendto()'))

        # the server is expected to send the value it received, for example:
        #   'server recvfrom() return 14.\n'
        #   'server sendto() 14 return 14.\n'

        m = re.search(r'(?P<num>\d+)\.\s+\Z', logged[-2])
        self.assertIsNotNone(m, 'could not extract numeric value from log message')

        num = m.group('num')
        msg = logged[-1].strip()

        self.assertTrue(msg.endswith(f'{num} return {num}.'))

    def test_http_elf_linux_x8664(self):
        PORT = 20020

        def picohttpd():
            ql = Qiling([fr'{X64_LINUX_ROOTFS}/bin/picohttpd', f'{PORT:d}'], X64_LINUX_ROOTFS, multithread=True, verbose=QL_VERBOSE.DEBUG)
            ql.run()

        picohttpd_therad = threading.Thread(target=picohttpd, daemon=True)
        picohttpd_therad.start()

        time.sleep(1)

        conn = http.client.HTTPConnection('localhost', PORT, timeout=10)
        conn.request('GET', '/')

        response = conn.getresponse()
        feedback = response.read()
        self.assertEqual('httpd_test_successful', feedback.decode())

    def test_http_elf_linux_arm(self):
        PORT = 20021

        def picohttpd():
            ql = Qiling([fr'{ARM_LINUX_ROOTFS}/bin/picohttpd', f'{PORT:d}'], ARM_LINUX_ROOTFS, multithread=True, verbose=QL_VERBOSE.DEBUG)
            ql.run()

        picohttpd_therad = threading.Thread(target=picohttpd, daemon=True)
        picohttpd_therad.start()

        time.sleep(1)

        conn = http.client.HTTPConnection('localhost', PORT, timeout=10)
        conn.request('GET', '/')

        response = conn.getresponse()
        feedback = response.read()
        self.assertEqual('httpd_test_successful', feedback.decode())

    def test_http_elf_linux_armeb(self):
        PORT = 20022

        def picohttpd():
            ql = Qiling([fr'{ARMEB_LINUX_ROOTFS}/bin/picohttpd', f'{PORT:d}'], ARMEB_LINUX_ROOTFS, multithread=True, verbose=QL_VERBOSE.DEBUG)
            ql.run()

        picohttpd_thread = threading.Thread(target=picohttpd, daemon=True)
        picohttpd_thread.start()

        time.sleep(1)

        # armeb libc uses statx to query stdout stats, but fails because 'stdout' is not a valid
        # path on the hosting paltform. it prints out the "Server started" message, but stdout is
        # not found and the message is kept buffered in.
        #
        # later on, picohttpd dups the client socket into stdout fd and uses ordinary printf to
        # send data out. however, when the "successful" message is sent, it is sent along with
        # the buffered message, which arrives first and raises a http.client.BadStatusLine exception
        # as it reads as a malformed http response.
        #
        # here we use a raw 'recv' method instead of 'getresponse' to work around that.

        conn = http.client.HTTPConnection('localhost', PORT, timeout=10)
        conn.request('GET', '/')

        feedback = conn.sock.recv(96).decode()
        self.assertTrue(feedback.endswith('httpd_test_successful'))


if __name__ == "__main__":
    unittest.main()
