#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling


def ql_syscall_rseq(ql: Qiling, rseq: int, rseq_len: int, flags: int, sig: int):
    # indicate rseq is not supported by this kernel
    # return -ENOSYS

    return 0
