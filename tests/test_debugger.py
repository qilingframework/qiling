#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import sys, subprocess, threading, unittest, socket, time
sys.path.append("..")
from qiling import *
from qiling.exception import *

def checksum(data):
    checksum = 0
    for c in data:
        if type(c) == str:
            checksum += (ord(c))
        else:
            checksum += c
    return checksum & 0xff

class DebuggerTest(unittest.TestCase):
    
    def test_gdbdebug_server(self):
        DELAY = 0.1
        ql = Qiling(["../examples/rootfs/x8664_linux/bin/x8664_hello"], "../examples/rootfs/x8664_linux", output ="debug")
        ql.debugger = True

        debugger_therad =  threading.Thread(target=ql.run, daemon=True)
        debugger_therad.start()
        time.sleep(DELAY)

        def send_raw(r):
            self.netout.write(r)
            self.netout.flush()
        
        def send(msg):
            time.sleep(DELAY) 
            send_raw('$%s#%.2x' % (msg, checksum(msg)))

        # some random command test just to make sure we covered most of the command
        self.gdb_client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.netin      = self.gdb_client.makefile('r')
        self.netout     = self.gdb_client.makefile('w')
        self.gdb_client.connect(('127.0.0.1',9999))
        send("qSupported:multiprocess+;swbreak+;hwbreak+;qRelocInsn+;fork-events+;vfork-events+;exec-events+;vContSupported+;QThreadEvents+;no-resumed+;xmlRegisters=i386")
        send("vMustReplyEmpty")
        send("QStartNoAckMode")
        send("Hgp0.0")
        send("qXfer:auxv:read::0,1000")
        send("?")
        send("qXfer:threads:read::0,fff")
        send("qAttached:2048")
        send("qC")
        send("g")
        send("m555555554040,1f8")
        send("m555555554000,100")
        send("m200,100")
        send("p10")
        send("Z0,555555554ada,1")
        send("c")
        send("")
        self.gdb_client.close()

if __name__ == "__main__":
    unittest.main()