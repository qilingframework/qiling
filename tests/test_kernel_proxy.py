#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
import struct
import unittest
import platform

sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_INTERCEPT, QL_VERBOSE


@unittest.skipUnless(platform.system() == 'Linux', 'kernel proxy requires Linux host')
class KernelProxyTest(unittest.TestCase):
    """Tests for the hybrid kernel proxy (Phase 0)."""

    ROOTFS = "../examples/rootfs/x8664_linux"
    HELLO_BIN = "../examples/rootfs/x8664_linux/bin/x8664_hello"

    # -------------------------------------------------------------------------
    # Proxy lifecycle
    # -------------------------------------------------------------------------

    def test_proxy_start_stop(self):
        """Proxy starts and stops cleanly."""
        from qiling.os.posix.kernel_proxy import KernelProxy

        ql = Qiling([self.HELLO_BIN], self.ROOTFS, verbose=QL_VERBOSE.OFF)
        proxy = KernelProxy(ql)

        self.assertIsNotNone(proxy._process)
        self.assertIsNotNone(proxy._client)
        self.assertTrue(proxy._process.poll() is None)  # still running

        proxy.stop()
        self.assertIsNone(proxy._process)
        self.assertIsNone(proxy._client)

        del ql

    def test_no_proxy_no_change(self):
        """Without proxy, Qiling behaves identically."""
        from qiling.extensions import pipe

        ql = Qiling([self.HELLO_BIN], self.ROOTFS, verbose=QL_VERBOSE.OFF)
        ql.os.stdout = pipe.SimpleOutStream(1)
        ql.run()

        self.assertIn(b"Hello", ql.os.stdout.read(1024))
        del ql

    def test_proxy_attached_no_forwarding(self):
        """Proxy attached but no syscalls forwarded — no behavior change."""
        from qiling.os.posix.kernel_proxy import KernelProxy
        from qiling.extensions import pipe

        ql = Qiling([self.HELLO_BIN], self.ROOTFS, verbose=QL_VERBOSE.OFF)
        ql.os.stdout = pipe.SimpleOutStream(1)
        proxy = KernelProxy(ql)

        ql.run()
        proxy.stop()

        self.assertIn(b"Hello", ql.os.stdout.read(1024))
        del ql

    # -------------------------------------------------------------------------
    # Raw syscall forwarding (integer-only args)
    # -------------------------------------------------------------------------

    def test_forward_getpid(self):
        """Forward getpid — proxy returns its own PID."""
        from qiling.os.posix.kernel_proxy import KernelProxy

        ql = Qiling([self.HELLO_BIN], self.ROOTFS, verbose=QL_VERBOSE.OFF)
        proxy = KernelProxy(ql)
        proxy.forward_syscall('getpid')

        results = []

        def on_getpid_exit(ql, *args):
            results.append(args[-1])

        ql.os.set_syscall('getpid', on_getpid_exit, QL_INTERCEPT.EXIT)
        ql.run()

        # if getpid was called, it should return the proxy's PID
        if results:
            self.assertEqual(results[0], proxy._process.pid)

        proxy.stop()
        del ql

    def test_forward_brk(self):
        """Forward brk to real kernel — binary still runs correctly."""
        from qiling.os.posix.kernel_proxy import KernelProxy
        from qiling.extensions import pipe

        ql = Qiling([self.HELLO_BIN], self.ROOTFS, verbose=QL_VERBOSE.OFF)
        ql.os.stdout = pipe.SimpleOutStream(1)
        proxy = KernelProxy(ql)
        proxy.forward_syscall('brk')

        brk_results = []

        def on_brk_exit(ql, *args):
            brk_results.append(args[-1])

        ql.os.set_syscall('brk', on_brk_exit, QL_INTERCEPT.EXIT)
        ql.run()
        proxy.stop()

        # brk is called during libc init
        self.assertGreater(len(brk_results), 0, "brk was never called")
        # binary should still produce correct output
        self.assertIn(b"Hello", ql.os.stdout.read(1024))
        del ql

    # -------------------------------------------------------------------------
    # FD-returning syscalls (returns_fd=True)
    # -------------------------------------------------------------------------

    def test_forward_returns_fd(self):
        """forward_syscall with returns_fd=True creates ql_proxy_fd in FD table."""
        from qiling.os.posix.kernel_proxy import KernelProxy
        from qiling.os.posix.kernel_proxy.proxy_fd import ql_proxy_fd

        ql = Qiling([self.HELLO_BIN], self.ROOTFS, verbose=QL_VERBOSE.OFF)
        proxy = KernelProxy(ql)
        proxy.forward_syscall('eventfd2', returns_fd=True)

        # call the forwarder directly (simulates binary calling eventfd2)
        hook = ql.os.posix_syscall_hooks[QL_INTERCEPT.CALL].get('ql_syscall_eventfd2')
        self.assertIsNotNone(hook, "forwarder hook not registered")

        guest_fd = hook(ql, 0, 0)
        self.assertGreaterEqual(guest_fd, 0)

        fd_obj = ql.os.fd[guest_fd]
        self.assertIsInstance(fd_obj, ql_proxy_fd)

        # write and read through the proxy FD
        fd_obj.write(struct.pack('<Q', 42))
        data = fd_obj.read(8)
        self.assertEqual(struct.unpack('<Q', data)[0], 42)

        fd_obj.close()
        proxy.stop()
        del ql

    def test_proxy_fd_dup(self):
        """ql_proxy_fd.dup() creates a working copy."""
        from qiling.os.posix.kernel_proxy import KernelProxy
        from qiling.os.posix.kernel_proxy.proxy_fd import ql_proxy_fd

        ql = Qiling([self.HELLO_BIN], self.ROOTFS, verbose=QL_VERBOSE.OFF)
        proxy = KernelProxy(ql)
        proxy.forward_syscall('eventfd2', returns_fd=True)

        hook = ql.os.posix_syscall_hooks[QL_INTERCEPT.CALL]['ql_syscall_eventfd2']
        guest_fd = hook(ql, 0, 0)
        fd_obj = ql.os.fd[guest_fd]

        duped = fd_obj.dup()
        self.assertIsInstance(duped, ql_proxy_fd)
        self.assertNotEqual(fd_obj._proxy_fd, duped._proxy_fd)

        # write on original, read on dup
        fd_obj.write(struct.pack('<Q', 7))
        data = duped.read(8)
        self.assertEqual(struct.unpack('<Q', data)[0], 7)

        fd_obj.close()
        duped.close()
        proxy.stop()
        del ql

    # -------------------------------------------------------------------------
    # User hooks coexist with proxy hooks
    # -------------------------------------------------------------------------

    def test_user_exit_hook_fires_on_forwarded_syscall(self):
        """User EXIT hook fires after proxy CALL hook."""
        from qiling.os.posix.kernel_proxy import KernelProxy

        ql = Qiling([self.HELLO_BIN], self.ROOTFS, verbose=QL_VERBOSE.OFF)
        proxy = KernelProxy(ql)
        proxy.forward_syscall('brk')

        exit_hook_called = []

        def on_exit(ql, *args):
            exit_hook_called.append(True)

        ql.os.set_syscall('brk', on_exit, QL_INTERCEPT.EXIT)
        ql.run()
        proxy.stop()

        self.assertGreater(len(exit_hook_called), 0,
                           "EXIT hook never fired on forwarded syscall")
        del ql

    def test_user_enter_hook_fires_on_forwarded_syscall(self):
        """User ENTER hook fires before proxy CALL hook."""
        from qiling.os.posix.kernel_proxy import KernelProxy

        ql = Qiling([self.HELLO_BIN], self.ROOTFS, verbose=QL_VERBOSE.OFF)
        proxy = KernelProxy(ql)
        proxy.forward_syscall('brk')

        enter_hook_called = []

        def on_enter(ql, *args):
            enter_hook_called.append(args)
            return None  # don't override args

        ql.os.set_syscall('brk', on_enter, QL_INTERCEPT.ENTER)
        ql.run()
        proxy.stop()

        self.assertGreater(len(enter_hook_called), 0,
                           "ENTER hook never fired on forwarded syscall")
        del ql

    def test_user_call_hook_overrides_proxy(self):
        """User CALL hook registered after proxy takes priority."""
        from qiling.os.posix.kernel_proxy import KernelProxy
        from qiling.extensions import pipe

        ql = Qiling([self.HELLO_BIN], self.ROOTFS, verbose=QL_VERBOSE.OFF)
        ql.os.stdout = pipe.SimpleOutStream(1)
        proxy = KernelProxy(ql)
        proxy.forward_syscall('brk')

        custom_brk_called = []

        def my_brk(ql, addr):
            custom_brk_called.append(addr)
            # return a fake address
            return 0x700000

        # register user CALL hook AFTER proxy — should override
        ql.os.set_syscall('brk', my_brk, QL_INTERCEPT.CALL)
        ql.run()
        proxy.stop()

        self.assertGreater(len(custom_brk_called), 0,
                           "user CALL hook should override proxy hook")
        del ql

    # -------------------------------------------------------------------------
    # IPC protocol
    # -------------------------------------------------------------------------

    def test_ipc_roundtrip(self):
        """IPC serialization/deserialization is correct."""
        from qiling.os.posix.kernel_proxy.ipc import (
            HEADER_FMT, HEADER_SIZE,
            SYSCALL_REQ_FMT, SYSCALL_RESP_FMT,
            FD_OP_REQ_FMT, FD_OP_RESP_FMT,
            MsgType, FdOp
        )
        import struct

        # syscall request roundtrip
        payload = struct.pack(SYSCALL_REQ_FMT, 39, 1, 2, 3, 4, 5, 6)
        nr, a0, a1, a2, a3, a4, a5 = struct.unpack(SYSCALL_REQ_FMT, payload)
        self.assertEqual(nr, 39)
        self.assertEqual((a0, a1, a2, a3, a4, a5), (1, 2, 3, 4, 5, 6))

        # syscall response roundtrip
        payload = struct.pack(SYSCALL_RESP_FMT, -2, 2)  # -ENOENT
        retval, errno_val = struct.unpack(SYSCALL_RESP_FMT, payload)
        self.assertEqual(retval, -2)
        self.assertEqual(errno_val, 2)

    # -------------------------------------------------------------------------
    # Error handling
    # -------------------------------------------------------------------------

    def test_forward_invalid_syscall_name(self):
        """forward_syscall with bogus name raises QlErrorSyscallNotFound."""
        from qiling.os.posix.kernel_proxy import KernelProxy
        from qiling.exception import QlErrorSyscallNotFound

        ql = Qiling([self.HELLO_BIN], self.ROOTFS, verbose=QL_VERBOSE.OFF)
        proxy = KernelProxy(ql)

        with self.assertRaises(QlErrorSyscallNotFound):
            proxy.forward_syscall('nonexistent_syscall_xyz')

        proxy.stop()
        del ql

    def test_forward_syscall_error_returns_negative_errno(self):
        """Forwarded syscall that fails returns negative errno."""
        from qiling.os.posix.kernel_proxy import KernelProxy

        ql = Qiling([self.HELLO_BIN], self.ROOTFS, verbose=QL_VERBOSE.OFF)
        proxy = KernelProxy(ql)

        # directly test via the IPC client: close an invalid FD
        retval = proxy._client.syscall(
            proxy._get_host_syscall_nr('close'),
            (9999, 0, 0, 0, 0, 0)
        )
        # should return -EBADF (-9)
        self.assertEqual(retval, -9)

        proxy.stop()
        del ql

    # -------------------------------------------------------------------------
    # Syscall table resolution
    # -------------------------------------------------------------------------

    def test_host_table_loaded(self):
        """Host syscall table resolves common syscalls."""
        from qiling.os.posix.kernel_proxy import KernelProxy

        ql = Qiling([self.HELLO_BIN], self.ROOTFS, verbose=QL_VERBOSE.OFF)
        proxy = KernelProxy(ql)

        for name in ['read', 'write', 'close', 'socket', 'epoll_create1']:
            nr = proxy._get_host_syscall_nr(name)
            self.assertIsInstance(nr, int)
            self.assertGreaterEqual(nr, 0)

        proxy.stop()
        del ql

    def test_guest_table_reverse_lookup(self):
        """Guest syscall name resolves to correct number."""
        from qiling.os.posix.kernel_proxy import KernelProxy

        ql = Qiling([self.HELLO_BIN], self.ROOTFS, verbose=QL_VERBOSE.OFF)
        proxy = KernelProxy(ql)

        # x8664: write is syscall 1
        nr = proxy._resolve_syscall_nr('write')
        self.assertEqual(nr, 1)

        # x8664: epoll_create1 is syscall 291
        nr = proxy._resolve_syscall_nr('epoll_create1')
        self.assertEqual(nr, 291)

        proxy.stop()
        del ql


    # -------------------------------------------------------------------------
    # FD translation (#3)
    # -------------------------------------------------------------------------

    def test_fd_arg_translated_to_proxy_fd(self):
        """When a forwarded syscall's arg is declared FD, the guest fd is replaced
        with the underlying proxy fd before forwarding."""
        from qiling.os.posix.kernel_proxy import KernelProxy, FD
        from qiling.os.posix.kernel_proxy.proxy_fd import ql_proxy_fd

        ql = Qiling([self.HELLO_BIN], self.ROOTFS, verbose=QL_VERBOSE.OFF)
        proxy = KernelProxy(ql)
        proxy.forward_syscall('close', arg_types=(FD,))

        # capture what gets sent over IPC
        sent = []
        original_syscall = proxy._client.syscall

        def spy(nr, args):
            sent.append((nr, tuple(args)))
            return 0  # pretend the kernel accepted

        proxy._client.syscall = spy

        # plant a ql_proxy_fd at guest_fd=42 with a chosen proxy_fd value
        guest_fd = 42
        fake_proxy_fd = 9999
        ql.os.fd[guest_fd] = ql_proxy_fd(proxy._client, fake_proxy_fd)

        close_hook = ql.os.posix_syscall_hooks[QL_INTERCEPT.CALL]['ql_syscall_close']
        close_hook(ql, guest_fd)

        self.assertEqual(len(sent), 1)
        _nr, args = sent[0]
        self.assertEqual(args[0], fake_proxy_fd,
                         f"expected proxy_fd={fake_proxy_fd} forwarded, got args={args}")

        proxy._client.syscall = original_syscall
        ql.os.fd[guest_fd] = None
        proxy.stop()
        del ql

    def test_fd_arg_rejects_non_proxy_fd(self):
        """Forwarding with FD arg type rejects non-proxy guest FDs."""
        from qiling.os.posix.kernel_proxy import KernelProxy, FD
        from qiling.exception import QlErrorSyscallError

        ql = Qiling([self.HELLO_BIN], self.ROOTFS, verbose=QL_VERBOSE.OFF)
        proxy = KernelProxy(ql)
        proxy.forward_syscall('close', arg_types=(FD,))

        close_hook = ql.os.posix_syscall_hooks[QL_INTERCEPT.CALL]['ql_syscall_close']

        # stdin (fd 0) is a regular ql_pipe, not a proxy fd
        with self.assertRaises(QlErrorSyscallError):
            close_hook(ql, 0)

        proxy.stop()
        del ql

    # -------------------------------------------------------------------------
    # Pointer marshaling (#2)
    # -------------------------------------------------------------------------

    def test_ptr_out_writes_back_to_guest_memory(self):
        """PtrOut buffer is written back into guest memory after the syscall.

        Uses pipe2(int pipefd[2], int flags) — pipefd is an output buffer of
        2 * sizeof(int) = 8 bytes containing the read/write FDs created by
        the kernel.
        """
        from qiling.os.posix.kernel_proxy import KernelProxy, PtrOut

        ql = Qiling([self.HELLO_BIN], self.ROOTFS, verbose=QL_VERBOSE.OFF)
        proxy = KernelProxy(ql)
        proxy.forward_syscall('pipe2', arg_types=(PtrOut(size=8), 'int'))

        # pick a free guest address and map it
        addr = 0x800000
        ql.mem.map(addr, 0x1000)
        ql.mem.write(addr, b'\xff' * 8)  # poison so we can detect the writeback

        hook = ql.os.posix_syscall_hooks[QL_INTERCEPT.CALL]['ql_syscall_pipe2']
        retval = hook(ql, addr, 0)
        self.assertEqual(retval, 0)

        raw = bytes(ql.mem.read(addr, 8))
        rfd, wfd = struct.unpack('<ii', raw)
        # the proxy returns kernel-side FDs; both must be valid (>=0) and distinct
        self.assertGreaterEqual(rfd, 0)
        self.assertGreaterEqual(wfd, 0)
        self.assertNotEqual(rfd, wfd)

        # clean up the proxy-side FDs the kernel just gave us
        import os as _os
        _os.close(rfd)
        _os.close(wfd)

        proxy.stop()
        del ql

    def test_ptr_in_reads_guest_memory(self):
        """PtrIn buffer is copied from guest memory and the proxy sees the data.

        Uses write(int fd, const void *buf, size_t count) on stderr (fd 2).
        We can't easily inspect proxy's stderr, but a successful return value
        equal to count proves the data was forwarded — write would otherwise
        return -EFAULT for a bad pointer or short for less data.
        """
        from qiling.os.posix.kernel_proxy import KernelProxy, PtrIn

        ql = Qiling([self.HELLO_BIN], self.ROOTFS, verbose=QL_VERBOSE.OFF)
        proxy = KernelProxy(ql)
        proxy.forward_syscall('write', arg_types=('int', PtrIn(size=lambda a: a[2]), 'int'))

        addr = 0x800000
        payload = b'kernel_proxy ptr_in roundtrip\n'
        ql.mem.map(addr, 0x1000)
        ql.mem.write(addr, payload)

        # forward stderr (fd 2 in the proxy is our subprocess's stderr,
        # which goes to the test runner — harmless)
        hook = ql.os.posix_syscall_hooks[QL_INTERCEPT.CALL]['ql_syscall_write']
        retval = hook(ql, 2, addr, len(payload))
        self.assertEqual(retval, len(payload))

        proxy.stop()
        del ql

    def test_ptr_size_callable(self):
        """PtrIn/PtrOut accept a size callable that depends on other args."""
        from qiling.os.posix.kernel_proxy import PtrIn, PtrOut

        ptr = PtrIn(size=lambda args: args[2] * 4)
        self.assertEqual(ptr.resolve((0, 0, 5)), 20)

        ptr2 = PtrOut(size=12)
        self.assertEqual(ptr2.resolve((0, 0, 0)), 12)

    # -------------------------------------------------------------------------
    # Reference cycle (#4)
    # -------------------------------------------------------------------------

    def test_no_reference_cycle_via_hook(self):
        """The forwarder closure holds only a weakref to KernelProxy, so the
        proxy can be garbage-collected once the user drops their reference,
        even though the hook is still registered on ql.os."""
        import gc
        import weakref
        from qiling.os.posix.kernel_proxy import KernelProxy

        ql = Qiling([self.HELLO_BIN], self.ROOTFS, verbose=QL_VERBOSE.OFF)
        proxy = KernelProxy(ql)
        proxy.forward_syscall('getpid')
        proxy.forward_syscall('eventfd2', returns_fd=True)

        wref = weakref.ref(proxy)
        proxy.stop()  # tear down the subprocess but leave the hooks registered
        del proxy
        gc.collect()

        self.assertIsNone(wref(),
                          "KernelProxy survived after stop()+del — closure must hold "
                          "a strong ref (cycle), defeating the weakref design")

        del ql


if __name__ == "__main__":
    unittest.main()
