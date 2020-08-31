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

    def _debugger(ql, remotedebugsrv, ip=None, port=None):
        if ip is None:
            ip = '127.0.0.1'
        
        if port is None:
            port = 9999
        else:
            port = int(port)

        remotedebugsrv = str(remotedebugsrv) + "server" 
        debugsession = str.upper(remotedebugsrv) + "session"
        debugsession = ql_get_module_function("qiling.debugger." + remotedebugsrv + "." + remotedebugsrv, debugsession)
        ql.debugger = debugsession(ql, ip, port)

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
                _debugger(ql, remotedebugsrv)
            else:
                _debugger(ql, remotedebugsrv, ip, port)
        
        except KeyboardInterrupt:
            if ql.remote_debug():
                ql.remote_debug.close()
            raise QlErrorOutput("[!] Remote debugging session ended")