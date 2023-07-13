#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

# Setup:
# - Unpack firmware rootfs (assumed hereby: 'rootfs/netgear_r6220')
# - The firmware expects '/dev/mtdblock11' to exist and be functional, otherwise it crashes
#   - cd rootfs/netgear_r6220/dev
#   - dd if=/dev/zero of=mtdblock11 bs=1024 count=129030
#   - mkfs.ext4 mtdblock11
#
# Run:
#  $ PYTHONPATH=/path/to/qiling ROOTFS=/path/to/netgear_rootfs python3 netgear_6220.py
#
# Emulation:
#  Soon after Qiling starts emulating the firmware it will look like it is done running, but actually it
#  isn't. During the emulation a few OS child processes are spawned, waiting for connection. To see them
#  run 'ps | grep python3'.
#
#  Once a connection is established on 127.0.0.1:8080, more child processes will be spawned. Note that in
#  case a child process dies with an exception, it turns into a zombie process. To kill the spawned child
#  processes, run 'pkill python3'

from typing import List
import logging
import os

import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_INTERCEPT, QL_VERBOSE
from qiling.log import QlColoredFormatter, QlBaseFormatter


# user may set 'ROOTFS' environment variable to use as rootfs
ROOTFS = os.environ.get('ROOTFS', r'./rootfs/netgear_r6220')


def __onexit_fork(ql: Qiling, retval: int) -> None:
    # as the emulated binary forks more and more child processes, it becomes hard to keep track
    # of their log entries and tell them apart. here we intercept the 'fork' system call on-exit
    # (i.e. after it was already simulated, but before resuming emulation) and modify the newly
    # created qiling instance's logger to show the os child processes id as part of the logs.
    #
    # note: os process id should not be confused with the internal qiling thread id, which does
    # not exist here since we do not use qiling multithreading feature.

    # fork returns 0 on the newly created child process
    if retval == 0:
        GREEN = '\033[92m'
        DEFAULT = '\033[39m'

        def __add_color(s: str) -> str:
            """Colorize text.
            """

            return f'{GREEN}{s}{DEFAULT}'

        def __do_nothing(s: str) -> str:
            """Use text as-is.
            """

            return s

        # patch current logger instance handlers to show the process id
        for h in ql.log.handlers:
            formatter = h.formatter

            if isinstance(formatter, QlColoredFormatter):
                fmt = __add_color

            elif isinstance(formatter, QlBaseFormatter):
                fmt = __do_nothing

            else:
                raise RuntimeError('unexpected formatter class')

            style = logging.PercentStyle(f'%(levelname)s {fmt(f"[{os.getpid():4d}]")} %(message)s')

            formatter._style = style
            formatter._fmt = style._fmt


def my_sandbox(path: List[str], rootfs: str) -> None:
    ql = Qiling(path, rootfs, profile='netgear_6220.ql', verbose=QL_VERBOSE.DEBUG)

    ql.add_fs_mapper(r'/proc', r'/proc')
    ql.os.set_syscall('fork', __onexit_fork, QL_INTERCEPT.EXIT)

    ql.run()


if __name__ == '__main__':
    argv = [
        f'{ROOTFS}/bin/mini_httpd',
        '-d', '/www',
        '-r', 'NETGEAR R6220',
        '-c', '**.cgi',
        '-t', '300'
    ]

    my_sandbox(argv, ROOTFS)
