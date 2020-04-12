#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import os, socket

from qiling.utils import *

def ql_debugger(ql, remotedebugsrv, ip=None, port=None):
    path = ql.path
    try:
        if ip is None:
            ip = '127.0.0.1'
        if port is None:
            port = 9999
        port = int(port) 
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((ip, port))
        ql.nprint("\ndebugger> Initializing loadbase 0x%x\n" % (ql.loader.loadbase))
        ql.nprint("debugger> Listening on %s:%u\n" % (ip, port))
        sock.listen(1)
        conn, addr = sock.accept()
    except:
        ql.nprint("debugger> Error: Address already in use\n")
        raise
    try:
        mappings = [(hex(ql.entry_point), 0x10)]
        exit_point = ql.entry_point + os.path.getsize(path)
        remotedebugsrv = debugger_convert_str(remotedebugsrv)
        remotedebugsrv = str(remotedebugsrv) + "server" 
        DEBUGSESSION = str.upper(remotedebugsrv) + "session"
        DEBUGSESSION = ql_get_module_function("qiling.debugger." + remotedebugsrv + "." + remotedebugsrv, DEBUGSESSION)
        ql.remotedebugsession = DEBUGSESSION(ql, conn, exit_point, mappings)
    except:
        ql.nprint("debugger> Error: Not able to initialize GDBServer\n")
        raise