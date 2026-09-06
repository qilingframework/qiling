#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import socket
import threading
import time
import unittest

import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE


class SimpleGdbClient:
    DELAY = 0.6

    def __init__(self, host: str, port: int):
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        txtf = sock.makefile('w')

        sock.connect((host, port))

        self.__sock = sock
        self.__file = txtf

    def __enter__(self):
        return self

    def __exit__(self, ex_type, ex_value, ex_traceback):
        self.__sock.close()

    @staticmethod
    def checksum(data: str) -> int:
        return sum(ord(c) for c in data) & 0xff

    def send(self, msg: str):
        time.sleep(SimpleGdbClient.DELAY)

        self.__file.write(f'${msg}#{SimpleGdbClient.checksum(msg):02x}')
        self.__file.flush()


class ReadingGdbClient:
    """A minimal gdb remote client that can also read replies, so tests can
    assert on the stop-reply packets the server sends back.
    """

    def __init__(self, host: str, port: int):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        sock.settimeout(10)

        self.__sock = sock
        self.__buf = b''

    def __enter__(self):
        return self

    def __exit__(self, ex_type, ex_value, ex_traceback):
        self.__sock.close()

    @staticmethod
    def checksum(data: str) -> int:
        return sum(ord(c) for c in data) & 0xff

    def send(self, msg: str):
        self.__sock.sendall(f'${msg}#{ReadingGdbClient.checksum(msg):02x}'.encode('latin'))

    def send_break(self):
        """Send an async interrupt: a bare '\x03' byte, outside of packet framing.
        """

        self.__sock.sendall(b'\x03')

    def read_packet(self) -> str:
        """Read a single '$<data>#<checksum>' reply, skipping any '+'/'-' acks.
        """

        # wait for a packet start marker
        while b'$' not in self.__buf:
            self.__buf += self.__sock.recv(4096)

        start = self.__buf.index(b'$')

        # wait until the terminating '#' and its two checksum digits arrived
        while True:
            end = self.__buf.find(b'#', start)
            if end != -1 and len(self.__buf) >= end + 3:
                break
            self.__buf += self.__sock.recv(4096)

        data = self.__buf[start + 1:end]
        self.__buf = self.__buf[end + 3:]

        return data.decode('latin')


class DebuggerTest(unittest.TestCase):
    def test_gdbdebug_file_server(self):
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/x8664_hello"], "../examples/rootfs/x8664_linux", verbose=QL_VERBOSE.DEBUG)
        ql.debugger = True

        # some random command test just to make sure we covered most of the command
        def gdb_test_client():
            # yield to allow ql to launch its gdbserver
            time.sleep(1.337 * 2)

            with SimpleGdbClient('127.0.0.1', 9999) as client:
                client.send('qSupported:multiprocess+;swbreak+;hwbreak+;qRelocInsn+;fork-events+;vfork-events+;exec-events+;vContSupported+;QThreadEvents+;no-resumed+;xmlRegisters=i386')
                client.send('vMustReplyEmpty')
                client.send('QStartNoAckMode')
                client.send('Hgp0.0')
                client.send('qXfer:auxv:read::0, 1000')
                client.send('?')
                client.send('qXfer:threads:read::0,fff')
                client.send(f'qAttached:{ql.os.pid}')
                client.send('qC')
                client.send('g')
                client.send('m555555554040, 1f8')
                client.send('m555555554000, 100')
                client.send('m200, 100')
                client.send('p10')
                client.send('Z0,555555554ada, 1')
                client.send('c')
                client.send('k')

                # yield to make sure ql gdbserver has enough time to receive our last command
                time.sleep(1.337)

        threading.Thread(target=gdb_test_client, daemon=True).start()

        ql.run()
        del ql

    def test_gdbdebug_mips32(self):
        ql = Qiling(["../examples/rootfs/mips32_linux/bin/mips32_hello"], "../examples/rootfs/mips32_linux", verbose=QL_VERBOSE.DEBUG)
        ql.debugger = True

        # some random command test just to make sure we covered most of the command
        def gdb_test_client():
            # yield to allow ql to launch its gdbserver
            time.sleep(1.337 * 2)

            with SimpleGdbClient('127.0.0.1', 9999) as client:
                client.send('qSupported:multiprocess+;swbreak+;hwbreak+;qRelocInsn+;fork-events+;vfork-events+;exec-events+;vContSupported+;QThreadEvents+;no-resumed+;xmlRegisters=i386')
                client.send('vMustReplyEmpty')
                client.send('QStartNoAckMode')
                client.send('Hgp0.0')
                client.send('qXfer:auxv:read::0, 1000')
                client.send('?')
                client.send('qXfer:threads:read::0,fff')
                client.send(f'qAttached:{ql.os.pid}')
                client.send('qC')
                client.send('g')
                client.send('m47ccd10,4')
                client.send('qXfer:threads:read::0,1000')
                client.send('m56555620,4')
                client.send('m5655561c,4')
                client.send('m56555620,4')
                client.send('m5655561c,4')
                client.send('m56555620,4')
                client.send('qTStatus')
                client.send('qTfP')
                client.send('m56555600,40')
                client.send('m56555620,4')
                client.send('Z0,47ccd10,4')
                client.send('QPassSignals:e;10;14;17;1a;1b;1c;21;24;25;2c;4c;97;')
                client.send('vCont?')
                client.send('vCont;c:pa410.-1')
                client.send('c')
                client.send('k')

                # yield to make sure ql gdbserver has enough time to receive our last command
                time.sleep(1.337)

        threading.Thread(target=gdb_test_client, daemon=True).start()

        ql.run()
        del ql

    def test_gdbdebug_armeb(self):
        ql = Qiling(["../examples/rootfs/armeb_linux/bin/armeb_hello"], "../examples/rootfs/armeb_linux", verbose=QL_VERBOSE.DEBUG)
        ql.debugger = True

        # some random command test just to make sure we covered most of the command
        def gdb_test_client():
            # yield to allow ql to launch its gdbserver
            time.sleep(1.337 * 2)

            with SimpleGdbClient('127.0.0.1', 9999) as client:
                client.send('qSupported:multiprocess+;swbreak+;hwbreak+;qRelocInsn+;fork-events+;vfork-events+;exec-events+;vContSupported+;QThreadEvents+;no-resumed+;xmlRegisters=i386')
                client.send('vMustReplyEmpty')
                client.send('QStartNoAckMode')
                client.send('Hgp0.0')
                client.send('qXfer:auxv:read::0, 1000')
                client.send('?')
                client.send('qXfer:threads:read::0,fff')
                client.send(f'qAttached:{ql.os.pid}')
                client.send('qC')
                client.send('g')
                client.send('m47ccd10,4')
                client.send('qXfer:threads:read::0,1000')
                client.send('z0,47ca5fc,4')
                client.send('m0,4')
                client.send('mfffffffc,4')
                client.send('m0,4')
                client.send('mfffffffc,4')
                client.send('m0,4')
                client.send('p1d')
                client.send('qTStatus')
                client.send('c')
                client.send('k')

                # yield to make sure ql gdbserver has enough time to receive our last command
                time.sleep(1.337)

        threading.Thread(target=gdb_test_client, daemon=True).start()

        ql.run()
        del ql

    def test_gdbdebug_stepi_reports_sigtrap(self):
        # regression for issues #1377 and #1538: a single-step ('s') used to be
        # answered with a SIGTERM stop-reply because emu_state is always STOPPED
        # after a step, which made gdb clients believe the program had died. the
        # stop-reply for an ordinary step must be a SIGTRAP ('S05'), never a
        # SIGTERM ('S0f').
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/x8664_hello"], "../examples/rootfs/x8664_linux", verbose=QL_VERBOSE.OFF)
        ql.debugger = 'gdb:127.0.0.1:9996'

        replies = []

        def gdb_test_client():
            # yield to allow ql to launch its gdbserver
            time.sleep(1.337 * 2)

            with ReadingGdbClient('127.0.0.1', 9996) as client:
                client.send('qSupported:multiprocess+;swbreak+;hwbreak+;vContSupported+;xmlRegisters=i386')
                client.read_packet()
                client.send('QStartNoAckMode')
                client.read_packet()

                # step a few instructions; every reply must be a SIGTRAP stop
                for _ in range(3):
                    client.send('s')
                    replies.append(client.read_packet())

                client.send('k')

        thread = threading.Thread(target=gdb_test_client, daemon=True)
        thread.start()

        ql.run()
        thread.join(timeout=30)
        del ql

        self.assertEqual(replies, ['S05', 'S05', 'S05'])

    def test_gdbdebug_vcont_signal_actions(self):
        # regression for issue #1377: a client resuming with a pending signal sends
        # a 'vCont;S<sig>' or 'vCont;C<sig>' action (e.g. 'S0f' after a stop-reply we
        # sent). the stub only recognized 'S05' and 'C05', replied empty to anything
        # else, and the client bailed out with 'Invalid remote reply'. any signal must
        # be accepted and carried out as a plain step or resume.
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/x8664_hello"], "../examples/rootfs/x8664_linux", verbose=QL_VERBOSE.OFF)
        ql.debugger = 'gdb:127.0.0.1:9995'

        replies = []

        def gdb_test_client():
            # yield to allow ql to launch its gdbserver
            time.sleep(1.337 * 2)

            with ReadingGdbClient('127.0.0.1', 9995) as client:
                client.send('qSupported:multiprocess+;swbreak+;hwbreak+;vContSupported+;xmlRegisters=i386')
                client.read_packet()
                client.send('QStartNoAckMode')
                client.read_packet()

                client.send('vCont?')
                replies.append(client.read_packet())

                # step while delivering SIGTERM; this is the packet reported in #1377
                client.send('vCont;S0f:p1.1;c:p1.-1')
                replies.append(client.read_packet())

                # resume while delivering SIGTERM; runs the guest to completion
                client.send('vCont;C0f:p1.1')
                replies.append(client.read_packet())

                client.send('k')

        thread = threading.Thread(target=gdb_test_client, daemon=True)
        thread.start()

        ql.run()
        thread.join(timeout=30)
        del ql

        self.assertEqual(replies[0], 'vCont;c;C;s;S')

        # the signalled step is an ordinary step: SIGTRAP, not an empty reply
        self.assertEqual(replies[1], 'S05')

        # the signalled resume ran to termination and reported an exit code
        self.assertTrue(replies[2].startswith('W'), f'unexpected reply to signalled resume: {replies[2]!r}')

    def test_gdbdebug_async_interrupt(self):
        # a free-running guest could not be interrupted at all: the stub is blocked
        # inside emu_start while the target runs, so the bare '\x03' break byte a
        # client sends to pause it was never read, and clients reported 'Cannot
        # execute this command while the target is running'. a break must stop the
        # guest and yield a SIGINT ('S02') stop-reply.
        INFINITE_LOOP = bytes.fromhex('90ebfd')  # nop ; jmp -3

        ql = Qiling(code=INFINITE_LOOP, archtype=QL_ARCH.X8664, ostype=QL_OS.LINUX, verbose=QL_VERBOSE.OFF)
        ql.debugger = 'gdb:127.0.0.1:9994'

        replies = []

        def gdb_test_client():
            # yield to allow ql to launch its gdbserver
            time.sleep(1.337 * 2)

            with ReadingGdbClient('127.0.0.1', 9994) as client:
                client.send('qSupported:multiprocess+;swbreak+;hwbreak+;vContSupported+;xmlRegisters=i386')
                client.read_packet()
                client.send('QStartNoAckMode')
                client.read_packet()

                # let the guest free-run; it never stops on its own
                client.send('c')

                # give it time to spin, then break into it
                time.sleep(1.337)
                client.send_break()

                try:
                    replies.append(client.read_packet())
                except OSError:
                    # the stub ignored the break and the guest is still spinning.
                    # stop it from here so the assertion below reports the failure
                    # instead of hanging the test run forever
                    ql.stop()

                client.send('k')

        thread = threading.Thread(target=gdb_test_client, daemon=True)
        thread.start()

        ql.run()
        thread.join(timeout=30)
        del ql

        self.assertEqual(replies, ['S02'])

    def test_gdbdebug_shellcode_server(self):
        X8664_LIN = bytes.fromhex('31c048bbd19d9691d08c97ff48f7db53545f995257545eb03b0f05')

        ql = Qiling(code=X8664_LIN, archtype=QL_ARCH.X8664, ostype=QL_OS.LINUX)
        ql.debugger = 'gdb:127.0.0.1:9998'

        def gdb_test_client():
            # yield to allow ql to launch its gdbserver
            time.sleep(1.337 * 2)

            with SimpleGdbClient('127.0.0.1', 9998) as client:
                client.send('qSupported:multiprocess+;swbreak+;hwbreak+;qRelocInsn+;fork-events+;vfork-events+;exec-events+;vContSupported+;QThreadEvents+;no-resumed+;xmlRegisters=i386')
                client.send('vMustReplyEmpty')
                client.send('QStartNoAckMode')
                client.send('Hgp0.0')
                client.send('?')
                client.send('qC')
                client.send('g')
                client.send('p10')
                client.send('c')
                client.send('k')

                # yield to make sure ql gdbserver has enough time to receive our last command
                time.sleep(1.337)

        threading.Thread(target=gdb_test_client, daemon=True).start()

        ql.run()
        del ql


if __name__ == "__main__":
    unittest.main()
