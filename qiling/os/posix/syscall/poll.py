from multiprocessing import Process

from qiling.const import *
from qiling.os.linux.thread import *
from qiling.os.posix.filestruct import *
from qiling.os.filestruct import *
from qiling.os.posix.const_mapping import *
from qiling.exception import *


def ql_syscall_poll(ql, fds, nfds, timeout, *args, **kw):
    return 0
