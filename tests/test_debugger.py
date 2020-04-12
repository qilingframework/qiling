#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import sys, subprocess, threading, unittest, socket, time
sys.path.append("..")
from qiling import *
from qiling.exception import *

class DebuggerTest(unittest.TestCase):
    def test_gdbdebug_server(self):
        DELAY = 1
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/x8664_hello"], "../examples/rootfs/x8664_linux")
        ql.debugger = True

        debugger_therad =  threading.Thread(target=ql.run, daemon=True)
        debugger_therad.start()
        time.sleep(DELAY)

        # refer to https://github.com/qilingframework/qiling/issues/112
        gdb_client = socket.socket()
        gdb_client.connect(('127.0.0.1',9999))
        gdb_client.send(b'qSupported:multiprocess+;swbreak+;hwbreak+;qRelocInsn+;fork-events+;vfork-events+;exec-events+;vContSupported+;QThreadEvents+;no-resumed+;xmlRegisters=i386')
        time.sleep(DELAY)
        gdb_client.send(b"vMustReplyEmpty")
        time.sleep(DELAY)
        gdb_client.send(b"QStartNoAckMode")
        time.sleep(DELAY)
        gdb_client.send(b"qXfer:auxv:read::0,1000")
        time.sleep(DELAY)    
        gdb_client.close()

if __name__ == "__main__":
    unittest.main()