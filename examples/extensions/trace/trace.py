#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions import trace

ROOTFS = r'examples/rootfs/x8664_linux'

if __name__ == '__main__':
    # qiling verbosity should be set to DEBUG to show the trace records
    ql = Qiling([fr'{ROOTFS}/bin/x8664_hello'], ROOTFS, verbose=QL_VERBOSE.DEBUG)

    # enable full tracing. since full tracing significantly slows down the emulation,
    # it may be enabled on demand from a hook, instead
    trace.enable_full_trace(ql)

    # sometimes all we need is to see the last operations that led to a crash. the history
    # method uses less resources compared to full trace, and emits trace records only when
    # a crash occurs.
    #
    # for example, showing last 32 trace records before the crash:
    # trace.enable_history_trace(ql, 32)

    ql.run()
