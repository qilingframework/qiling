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
            mappings = [(hex(ql.loader.entry_point), 0x10)]
            exit_point = ql.loader.entry_point + os.path.getsize(path)
            remotedebugsrv = debugger_convert_str(remotedebugsrv)
            remotedebugsrv = str(remotedebugsrv) + "server" 
            DEBUGSESSION = str.upper(remotedebugsrv) + "session"
            DEBUGSESSION = ql_get_module_function("qiling.debugger." + remotedebugsrv + "." + remotedebugsrv, DEBUGSESSION)
            ql.remotedebugsession = DEBUGSESSION(ql, conn, exit_point, mappings)
        except:
            ql.nprint("debugger> Error: Not able to initialize Debugging Server\n")
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
        raise QlErrorOutput("[!] Error: Debugger not supported\n")       
    else:
        try:
            if ql.debugger is True:
                ql_debugger(ql, remotedebugsrv)
            else:
                ql_debugger(ql, remotedebugsrv, ip, port)
        
        except KeyboardInterrupt:
            if ql.remotedebugsession():
                ql.remotedebugsession.close()
            raise QlErrorOutput("[!] Remote debugging session ended\n")
