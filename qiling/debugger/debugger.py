#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import socket
import os
from qiling.exception import QlErrorOutput
from qiling.const import QL_DEBUGGER
from qiling.utils import debugger_convert, debugger_convert_str, ql_get_module_function

def ql_debugger_init(ql):

    def ql_debugger(ql, remotedebugsrv, ip=None, port=None):
        path = ql.path
        try:
            if ip is None:
                ip = '127.0.0.1'
            if port is None:
                port = 9999

            port = int(port)
            
            if ql.shellcoder:
                load_address = ql.os.entry_point
                exit_point = load_address + len(ql.shellcoder)
            else:
                load_address = ql.loader.load_address
                exit_point = load_address + os.path.getsize(path)
                
            mappings = [(hex(load_address))]
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind((ip, port))
            ql.nprint("debugger> Initializing load_address 0x%x" % (load_address))
            ql.nprint("debugger> Listening on %s:%u" % (ip, port))
            sock.listen(1)
            conn, addr = sock.accept()
        except:
            ql.nprint("debugger> Error: Address already in use")
            raise
        try:

            remotedebugsrv = debugger_convert_str(remotedebugsrv)
            remotedebugsrv = str(remotedebugsrv) + "server" 
            DEBUGSESSION = str.upper(remotedebugsrv) + "session"
            DEBUGSESSION = ql_get_module_function("qiling.debugger." + remotedebugsrv + "." + remotedebugsrv, DEBUGSESSION)
            ql.remote_debug = DEBUGSESSION(ql, conn, exit_point, mappings)
        except:
            ql.nprint("debugger> Error: Not able to initialize Debugging Server")
            raise

    try:
        remotedebugsrv, ip, port = '', '', ''
        remotedebugsrv, ip, port = ql.debugger.split(':')
    except:
        ip, port = '', ''

    remotedebugsrv = "gdb"
    
    try:
        ip, port = ql.debugger.split(':')
        # If only ip:port is defined, remotedebugsrv is always gdb
    except:
        if ip is None:
            ip = "127.0.0.0"
        if port is None:
            port = "9999" 

    remotedebugsrv = debugger_convert(remotedebugsrv)

    if remotedebugsrv not in (QL_DEBUGGER):
        raise QlErrorOutput("[!] Error: Debugger not supported")       
    else:
        try:
            if ql.debugger is True:
                ql_debugger(ql, remotedebugsrv)
            else:
                ql_debugger(ql, remotedebugsrv, ip, port)
        
        except KeyboardInterrupt:
            if ql.remote_debug():
                ql.remote_debug.close()
            raise QlErrorOutput("[!] Remote debugging session ended")
