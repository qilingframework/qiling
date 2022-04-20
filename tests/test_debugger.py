#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys, threading, unittest, socket, time

sys.path.append("..")
from qiling import Qiling
from qiling.const import QL_VERBOSE

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

    def test_gdbdebug_shellcode_server(self):
        X8664_LIN = bytes.fromhex('31c048bbd19d9691d08c97ff48f7db53545f995257545eb03b0f05')

        ql = Qiling(code=X8664_LIN, archtype='x8664', ostype='linux')
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