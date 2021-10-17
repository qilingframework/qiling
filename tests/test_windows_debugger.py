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

    def test_pe_gdbdebug(self):
        ql = Qiling(["../examples/rootfs/x86_windows/bin/x86_hello.exe"], "../examples/rootfs/x86_windows/", verbose=QL_VERBOSE.DEBUG)
        ql.debugger = 'gdb:127.0.0.1:9996'

        # some random command test just to make sure we covered most of the command
        def gdb_test_client():
            # yield to allow ql to launch its gdbserver
            time.sleep(1.337 * 2)

            with SimpleGdbClient('127.0.0.1', 9996) as client:
                client.send('qSupported:multiprocess+;swbreak+;hwbreak+;qRelocInsn+;fork-events+;vfork-events+;exec-events+;vContSupported+;QThreadEvents+;no-resumed+;xmlRegisters=i386')
                client.send('vMustReplyEmpty')
                client.send('QStartNoAckMode')
                client.send('Hgp0.0')
                client.send('qXfer:auxv:read::0, 1000')
                client.send('?')
                client.send('qXfer:threads:read::0,fff')
                client.send('qAttached:'+ str(ql.os.pid))
                client.send('qC')
                client.send('g')
                client.send('m200, 100')
                client.send('p10')
                client.send('c')
                client.send('k')

                # yield to make sure ql gdbserver has enough time to receive our last command
                time.sleep(1.337)

        threading.Thread(target=gdb_test_client, daemon=True).start()

        ql.run()
        del ql

if __name__ == '__main__':
    unittest.main()