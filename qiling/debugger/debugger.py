#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import socket
import os
from qiling.exception import QlErrorOutput
from qiling.const import QL_DEBUGGER
from qiling.utils import debugger_convert, debugger_convert_str, ql_get_module_function
from qiling.debugger.qdb import Qdb

def ql_debugger_init(ql):

    def ql_debugger(ql, remotedebugsrv, ip=None, port=None):
        if ip is None:
            ip = '127.0.0.1'
        
        if port is None:
            port = 9999
        else:
            port = int(port)
        
        if ql.shellcoder:
            load_address = ql.os.entry_point
            exit_point = load_address + len(ql.shellcoder)
        else:
            load_address = ql.loader.load_address
            exit_point = load_address + os.path.getsize(ql.path)
            
        mappings = [(hex(load_address))]
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((ip, port))
        ql.nprint("debugger> Initializing load_address 0x%x" % (load_address))
        ql.nprint("debugger> Listening on %s:%u" % (ip, port))
        sock.listen(1)
        conn, addr = sock.accept()
        remotedebugsrv = str(remotedebugsrv) + "server" 
        debugsession = str.upper(remotedebugsrv) + "session"
        debugsession = ql_get_module_function("qiling.debugger." + remotedebugsrv + "." + remotedebugsrv, debugsession)
        ql.remote_debug = debugsession(ql, conn, exit_point, mappings)


    remotedebugsrv = "gdb"

    if ql.debugger != True:
        debug_opts = ql.debugger.split(':')

        if debug_opts[0] == "qdb":
            try:
                qdb_debug_opts = str(debug_opts[1]).split(',')
            except:
                qdb_debug_opts = ""    
            rr = "rr" in qdb_debug_opts
            ql.hook_address(Qdb.attach(rr=rr), ql.os.entry_point)
            return

        elif len(debug_opts) == 3:
            remotedebugsrv, ip, port = debug_opts

        elif len(debug_opts) == 2:
            ip, port = ql.debugger.split(':')
        else:
            raise QlErrorOutput("[!] Error: Debugger not supported")      


    if debugger_convert(remotedebugsrv) not in (QL_DEBUGGER):
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