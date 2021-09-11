#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import select
from typing import Tuple, Sequence, Mapping

from qiling import Qiling
from qiling.const import QL_VERBOSE

def ql_syscall__newselect(ql: Qiling, nfds: int, readfds: int, writefds: int, exceptfds: int, timeout: int):
    regreturn = 0

    def parse_fd_set(ql: Qiling, max_fd: int, struct_addr: int) -> Tuple[Sequence[int], Mapping[int, int]]:
        fd_list = []
        fd_map = {}

        if struct_addr:
            tmp = 0

            for i in range(max_fd):
                if i % 32 == 0:
                    tmp = ql.unpack32(ql.mem.read(struct_addr + i, 4))

                if tmp & 0x1:
                    fileno = ql.os.fd[i].fileno()

                    fd_list.append(fileno)
                    fd_map[fileno] = i

                tmp = tmp >> 1

        return fd_list, fd_map

    def set_fd_set(buf: bytes, idx: int) -> bytes:
        buf = buf[ : idx // 8] + bytes([buf[idx // 8] | (0x1 << (idx % 8))]) + buf[idx // 8 + 1 : ]
        return buf

    def handle_ready_fds(ptr: int, ready_fds: Sequence, fds_map: Mapping):
        tmp_buf = b'\x00' * (nfds // 8 + 1)

        for fd in ready_fds:
            tmp_buf = set_fd_set(tmp_buf, fds_map[fd])

        ql.mem.write(ptr, tmp_buf)

    tmp_r_fd, tmp_r_map = parse_fd_set(ql, nfds, readfds)
    tmp_w_fd, tmp_w_map = parse_fd_set(ql, nfds, writefds)
    tmp_e_fd, tmp_e_map = parse_fd_set(ql, nfds, exceptfds)

    n = ql.pointersize

    if timeout:
        sec  = ql.unpack(ql.mem.read(timeout + n * 0, n))
        usec = ql.unpack(ql.mem.read(timeout + n * 1, n))

        timeout_total = sec + float(usec) / 1000000
    else:
        timeout_total = None

    try:
        ready_rfds, ready_wfds, ready_efds = select.select(tmp_r_fd, tmp_w_fd, tmp_e_fd, timeout_total)
        regreturn = len(ready_rfds) + len(ready_wfds) + len(ready_efds)

        if readfds:
            handle_ready_fds(readfds, ready_rfds, tmp_r_map)

        if writefds:
            handle_ready_fds(writefds, ready_wfds, tmp_w_map)

        if exceptfds:
            handle_ready_fds(exceptfds, ready_efds, tmp_e_map)

    except KeyboardInterrupt:
        raise

    except:
        if ql.verbose >= QL_VERBOSE.DEBUG:
            raise

    return regreturn
