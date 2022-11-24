#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.const import QL_OS, QL_ENDIAN
from qiling.os import struct
import select
import ctypes


def ql_syscall_poll(ql: Qiling, fds: int, nfds: int, timeout: int):
    base = struct.BaseStructEL if ql.arch.endian == QL_ENDIAN.EL else struct.BaseStructEB

    class Pollfd(base):
        _fields_ = (
            ('fd', ctypes.c_int32),
            ('events', ctypes.c_int16),
            ('revents', ctypes.c_int16)
        )

    if ql.host.os == QL_OS.LINUX:
        fn_map = {}
        try:
            p = select.poll()
            for i in range(nfds):
                with Pollfd.ref(ql.mem, fds + ctypes.sizeof(Pollfd) * i) as pollfd:
                    # clear revents field
                    pollfd.revents = 0

                    ql.log.debug(f"register poll fd {pollfd.fd}, event {pollfd.events}")
                    fileno = ql.os.fd[pollfd.fd].fileno()
                    fn_map[fileno] = i
                    p.register(fileno, pollfd.events)

            res_list = p.poll(timeout)
            regreturn = len(res_list)

            for fn, revent in res_list:
                with Pollfd.ref(ql.mem, fds + ctypes.sizeof(Pollfd) * fn_map[fn]) as pollfd:
                    ql.log.debug(f"receive event on fd {pollfd.fd}, revent {revent}")
                    pollfd.revents = revent
        except Exception as e:
            ql.log.error(f'{e} {fds=}, {nfds=}, {timeout=}')
            regreturn = -1
                
        return regreturn
    else:
        ql.log.warning(f'syscall poll not implemented')
        return 0
