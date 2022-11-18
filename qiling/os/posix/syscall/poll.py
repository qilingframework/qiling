#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
import select

def ql_syscall_poll(ql: Qiling, fds: int, nfds: int, timeout: int):
    fn_map = {}
    try:
        p = select.poll()
        for i in range(nfds):
            fd = ql.mem.read_ptr(fds + i*8, 4)
            event = ql.mem.read_ptr(fds + i*8 + 4, 2)
            # clear revent field
            ql.mem.write_ptr(fds + i*8 + 6, 0, 2)

            ql.log.debug(f"register poll fd {fd}, event {event}")

            fileno = ql.os.fd[fd].fileno()
            fn_map[fileno] = {'idx': i, 'fd': fd}
            p.register(fileno, event)

        res_list = p.poll(timeout)
        regreturn = len(res_list)

        for fd, revent in res_list:
            ql.log.debug(f"receive event on fd {fn_map[fd]['fd']}, revent {revent}")
            idx = fn_map[fd]['idx']
            ql.mem.write_ptr(fds + idx*8 +6, revent, 2)
        
    except Exception as e:
        ql.log.error(f'{e} {fds=}, {nfds=}, {timeout=}')
        regreturn = -1
            
    return regreturn
