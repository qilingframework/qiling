#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import sys, subprocess, threading, unittest, socket, time
from binascii import unhexlify
sys.path.append("..")
from qiling import *
from qiling.exception import *

DELAY = 1

def checksum(data):
    checksum = 0
    for c in data:
        if type(c) == str:
            checksum += (ord(c))
        else:
            checksum += c
    return checksum & 0xff

def send_raw(netout, r):
    netout.write(r)
    netout.flush()
        
def send(netout, msg):
    time.sleep(DELAY) 
    send_raw(netout, '$%s#%.2x' % (msg, checksum(msg)))

class DebuggerTest(unittest.TestCase):
    
    def test_pe_gdbdebug(self):
        ql = Qiling(["../examples/rootfs/x86_windows/bin/x86_hello.exe"], "../examples/rootfs/x86_windows/", output ="debug")
        ql.debugger = "127.0.0.1:9996"

        # some random command test just to make sure we covered most of the command
        def gdb_test_client():
            time.sleep(DELAY)
            gdb_client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            netout     = gdb_client.makefile('w')
            gdb_client.connect(('127.0.0.1',9996))
            time.sleep(DELAY) 
            send(netout, "qSupported:multiprocess+;swbreak+;hwbreak+;qRelocInsn+;fork-events+;vfork-events+;exec-events+;vContSupported+;QThreadEvents+;no-resumed+;xmlRegisters=i386")
            time.sleep(DELAY) 
            send(netout, "vMustReplyEmpty")
            time.sleep(DELAY) 
            send(netout, "QStartNoAckMode")
            time.sleep(DELAY) 
            send(netout, "Hgp0.0")
            time.sleep(DELAY) 
            send(netout, "qXfer:auxv:read::0, 1000")
            time.sleep(DELAY) 
            send(netout, "?")
            time.sleep(DELAY) 
            send(netout, "qXfer:threads:read::0,fff")
            time.sleep(DELAY) 
            send(netout, "qAttached:"+ str(ql.os.pid))
            time.sleep(DELAY) 
            send(netout, "qC")
            time.sleep(DELAY) 
            send(netout, "g")
            time.sleep(DELAY) 
            send(netout, "m200, 100")
            time.sleep(DELAY) 
            send(netout, "p10")
            time.sleep(DELAY)
            send(netout, "c")
            time.sleep(DELAY)
            send(netout, "k")
            time.sleep(DELAY)
            gdb_client.close()

        debugger_file_therad =  threading.Thread(target=gdb_test_client, daemon=True)
        debugger_file_therad.start()
        
        ql.run()
        del ql

if __name__ == "__main__":
    unittest.main()