#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import socket
import unittest

from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
from qiling.os.posix.const import EAGAIN
from qiling.os.posix.filestruct import ql_socket
from qiling.os.posix.syscall.socket import ql_syscall_recv


class SocketTest(unittest.TestCase):
    def test_recv_on_nonblocking_socket_returns_eagain(self) -> None:
        ql = Qiling(code=b'\x00\x00\x00\x00', archtype=QL_ARCH.X8664, ostype=QL_OS.LINUX, verbose=QL_VERBOSE.OFF)
        host_sock, peer_sock = socket.socketpair()

        try:
            host_sock.setblocking(False)
            ql.os.fd[3] = ql_socket(host_sock)

            buf = ql.mem.map_anywhere(0x1000)

            self.assertEqual(ql_syscall_recv(ql, 3, buf, 16, 0), -EAGAIN)

        finally:
            ql.os.fd[3] = None
            host_sock.close()
            peer_sock.close()


if __name__ == "__main__":
    unittest.main()
