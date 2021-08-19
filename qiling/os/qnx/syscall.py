#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

try:
    from time import time_ns
except ImportError:
    from datetime import datetime
    # For compatibility with Python 3.6
    def time_ns():
        now = datetime.now()
        return int(now.timestamp() * 1e9)

from binascii import hexlify

from qiling import Qiling
from qiling.utils import ql_get_module_function
from qiling.os.posix.const_mapping import _constant_mapping
from qiling.os.qnx.helpers import get_message_body, QnxConn, ux32s
from qiling.os.qnx.map_msgtype import map_msgtype
from qiling.os.qnx.structs import *
from qiling.os.qnx.types import channel_create_flags, clock_types, connect_attach_flags
from qiling.os.qnx.message import *
from qiling.os.qnx.const import *

def ql_syscall_channel_create(ql:Qiling, flags, *args, **kw):
    # TODO: Can we ignore the flags?
    ql.log.debug(f'syscall_channel_create(flags = {_constant_mapping(flags, channel_create_flags)})')
    # return new Channel Id
    regreturn = ql.os.channel_id
    ql.os.channel_id += 1
    return regreturn

# Source: openqnx lib/c/support/_syspage_time.c
def ql_syscall_clock_time(ql:Qiling, id, new, old, *args, **kw):
    # check parameters
    
    if not id in clock_types:
        raise NotImplementedError(f'Unknown clock id {id} not implemented')
    if id != 0:
        raise NotImplementedError(f'Clock type {clock_types[id]} not implemented')
    # set time
    if new != 0:
        clock_new = ql.unpack64(ql.mem.read(new, 8))
        ql.log.warn(f'syscall_clock_time(id = {clock_types[id]}, new = {clock_new}) set time not supported')
        return -1
    # get time
    if old != 0:
        clock_old = ql.unpack64(ql.mem.read(old, 8))
        ql.log.debug(f'syscall_clock_time(id = {clock_types[id]}, old = {clock_old})')
        ql.mem.write(old, ql.pack64(time_ns()))
    
    return 0

def ql_syscall_connect_attach(ql:Qiling, nd, pid, chid, index, flags, *args, **kw):
    # check parameters
    assert (nd, flags) == (ND_LOCAL_NODE, connect_attach_flags['_NTO_COF_CLOEXEC']), "syscall_connect_attach parameters are wrong"
    ql.log.debug(f'syscall_connect_attach(nd = ND_LOCAL_NODE, pid = {pid}, chid = {chid}, index = 0x{index:x}, flags = _NTO_COF_CLOEXEC)')
    # return new Connection Id
    
    if index & NTO_SIDE_CHANNEL:
        regreturn = ql.os.connection_id_hi
        ql.os.connection_id_hi += 1
    else:
        regreturn = ql.os.connection_id_lo
        ql.os.connection_id_lo += 1
    
    assert not regreturn in ql.os.connections, "Connection Id is already in use"
    ql.os.connections[regreturn] = QnxConn(pid, chid)
    return regreturn

def ql_syscall_connect_detach(ql:Qiling, coid, *args, **kw):
    # check parameters
    assert coid in ql.os.connections, "Connection Id must exist in connections mapping"
    assert ql.os.connections[coid].fd == None, "File Descriptor has to be closed properly"
    ql.log.debug(f'connect_detach(coid = 0x{coid:x})')
    # close connection
    del ql.os.connections[coid]
    return 0

# Source: openqnx services/system/ker/ker_connect.c
def ql_syscall_connect_client_info(ql:Qiling, scoid, info, ngroups, *args, **kw):
    # scoid == -1 is used for the calling process
    
    if scoid != 0xffffffff:
        raise NotImplementedError("Other processes are not implemented")
    
    # struct _client_info in services/system/ker/ker_connect.c
    ql.mem.write(info, pack("<IiiI", ND_LOCAL_NODE, ql.os.pid, 0, 0))
    # info.cred is initialized with zero which stands for super-user, let's keep it this way
    return 0

def ql_syscall_connect_flags(ql:Qiling, pid, coid, mask, bits, *args, **kw):
    # check parameters
    assert pid == 0, "Is it possible to change the connection flags of another process?"
    assert coid in ql.os.connections, "Connection Id must exist in connections mapping"
    assert mask == 0x01, "Is the mask is always FD_CLOEXEC?"
    # lib/c/public/fcntl.h
    ql.log.debug(f'syscall_connect_flags(coid = 0x{coid:x}, flags = FD_CLOEXEC, bits = 0x{bits:x})')
    return 0

def ql_syscall_sys_cpupage_get(ql:Qiling, index, *args, **kw):
    # CPUPAGE_ADDR 
    
    if index == 0xffffffff:
        return ql.os.cpupage_addr
    # CPUPAGE_PLS
    elif index == 1:
        return ql.unpack32(ql.mem.read(ql.os.cpupage_addr + 4, 4))
    # CPUPAGE_SYSPAGE
    elif index == 2:
        return ql.os.syspage_addr

    ql.log.warning(f'ql_syscall_sys_cpupage_get (index {index:d}) not implemented')

def ql_syscall_sys_cpupage_set(ql:Qiling, index, value, *args, **kw):
    # CPUPAGE_PLS
    
    if index == 1:
        ql.mem.write(ql.os.cpupage_addr + 4, ql.pack32(value))
        return EOK

    ql.log.warning(f'ql_syscall_sys_cpupage_get (index {index:d}) not implemented')    

def ql_syscall_clock_cycles(ql, *args, **kw):
    # This syscall returns current core's free-running 64-bit counter value (e.g. RDTSC on x86)
    # For the sake of simplicity we just return current timestamp in nanoseconds
    return time_ns()

# Source: openqnx services/system/ker/ker_sync.c
def ql_syscall_sync_create(ql:Qiling, type, syncp, attrp, *args, **kw):
    attr = None

    if attrp:        
        attr = _sync_attr(ql, attrp).loadFromMem()

    if type == NTO_SYNC_MUTEX_FREE:
        count = NTO_SYNC_NONRECURSIVE
        if attr:
            if (attr._flags & PTHREAD_RECURSIVE_MASK) != PTHREAD_RECURSIVE_DISABLE:
                count &= ~NTO_SYNC_NONRECURSIVE

            if attr._flags & PTHREAD_ERRORCHECK_DISABLE:
                count |= NTO_SYNC_NOERRORCHECK
    else:
        ql.log.warning(f"Sync type {type:#08x} not implemented")
        return EINVAL

    sync = _sync(ql, syncp).loadFromMem()
    sync._count = count
    sync._owner = type
    sync.updateToMem()
    ql.log.debug(f'ql_syscall_sync_create: count={ux32s(sync._count)}, owner={ux32s(sync._owner)}')

    return EOK

# Source: openqnx services/system/ker/ker_sync.c
def ql_syscall_sync_mutex_lock(ql:Qiling, syncp, *args, **kw):    
    sync = _sync(ql, syncp).loadFromMem()
    ql.log.debug(f'ql_syscall_sync_mutex_lock: count={ux32s(sync._count)}, owner={ux32s(sync._owner)}')

    # TODO: implement proper mutexes instead of these stubs
    # Set mutex owner to current thread to make it look like we've got the mutex
    tls = _thread_local_storage(ql, ql.os.cpupage_tls_addr).loadFromMem()

    sync._owner = tls._owner
    sync.updateToMem()

    return EOK

# Source: openqnx services/system/ker/ker_sync.c
def ql_syscall_sync_mutex_unlock(ql:Qiling, syncp, *args, **kw):
    sync = _sync(ql, syncp).loadFromMem()
    ql.log.debug(f'ql_syscall_sync_mutex_unlock: count={ux32s(sync._count)}, owner={ux32s(sync._owner)}')

    # TODO: implement proper mutexes instead of these stubs
    # Reset mutex owner
    sync._owner = NTO_SYNC_MUTEX_FREE
    sync.updateToMem()

    return EOK

def ql_syscall_connect_client_info(ql:Qiling, scoid, info, ngroups, *args, **kw):
    return EOK

def ql_syscall_msg_sendv(ql:Qiling, coid, smsg, sparts, rmsg, rparts, *args, **kw):
    return _msg_sendv(ql, coid, smsg, sparts, rmsg, rparts, *args, **kw)

def ql_syscall_msg_sendvnc(ql:Qiling, coid, smsg, sparts, rmsg, rparts, *args, **kw):
    return _msg_sendv(ql, coid, smsg, sparts, rmsg, rparts, *args, **kw)

def _msg_sendv(ql:Qiling, coid, smsg, sparts, rmsg, rparts, *args, **kw):
    assert coid in ql.os.connections, "Connection Id must exist in connections mapping"
    conn = ql.os.connections[coid]
    if conn.pid == SYSMGR_PID and conn.chid == SYSMGR_CHID:
        sbody = get_message_body(ql, smsg, sparts)
        type_ = ql.unpack16(sbody[:2])

        msg_name = map_msgtype(ql, type_)
        _msg_handler = ql_get_module_function(f"qiling.os.qnx", "message")

        if msg_name in dir(_msg_handler):
            msg_hook = eval(msg_name)
            msg_name = msg_hook.__name__
        else:
            msg_hook = None
            msg_name = None

        if msg_hook:
            ret = msg_hook(ql, coid, smsg, sparts, rmsg, rparts, *args, **kw)
        else:
            ql.log.warning(f'_msg_sendv: no hook for message type {type_:#04x}')
            ret = -1
    else:
        ql.log.warn(f'syscall_msg_sendv(coid = {coid}): unhandled message for pid = {conn.pid}, chid = {conn.chid}')
        ret = -1

    return ret

def ql_syscall_thread_destroy(ql:Qiling, tid, priority, status, *args, **kw):
    # Requested to terminate all threads in the current process
    if tid == 0xffffffff and priority == 0xffffffff:
        ql.os.exit_code = status
        ql.os.stop()
    return EOK

def ql_syscall_signal_kill(ql:Qiling, nd, tid, pid, signo, code, value, *args, **kw):
    pass
