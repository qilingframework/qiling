#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.const import QL_OS, QL_ENDIAN
from qiling.os.posix.structs import *
import select
import ctypes


def ql_syscall_poll(ql: Qiling, fds: int, nfds: int, timeout: int):
    pollfd = make_pollfd(ql.arch.bits, ql.arch.endian)

    if ql.host.os == QL_OS.LINUX:
        fn_map = {}
        try:
            p = select.poll()
            for i in range(nfds):
                with pollfd.ref(ql.mem, fds + ctypes.sizeof(pollfd) * i) as pf:
                    # clear revents field
                    pf.revents = 0

                    ql.log.debug(f"register poll fd {pf.fd}, event {pf.events}")
                    fileno = ql.os.fd[pf.fd].fileno()
                    fn_map[fileno] = i
                    p.register(fileno, pf.events)

            res_list = p.poll(timeout)
            regreturn = len(res_list)

            for fn, revent in res_list:
                with pollfd.ref(ql.mem, fds + ctypes.sizeof(pollfd) * fn_map[fn]) as pf:
                    ql.log.debug(f"receive event on fd {pf.fd}, revent {revent}")
                    pf.revents = revent
        except Exception as e:
            ql.log.error(f'{e} {fds=}, {nfds=}, {timeout=}')
            regreturn = -1
                
        return regreturn
    else:
        ql.log.warning(f'syscall poll not implemented')
        return 0
