from qiling import *
from qiling.const import *
from qiling.os.posix.const import *
from qiling.os.const import *
from qiling.os.filestruct import ql_file
import select
from ctypes import *
from qiling.os import struct
import struct
from qiling.os.filestruct import PersistentQlFile
from qiling.extensions import pipe
import sys


class QlEpollObj:
    def __init__(self, epoll_object):
        self._epoll_object = epoll_object
        self._fds = {}  # key: fd, value: eventmask
        # keep track of which fds have what eventmasks,
        # since this isn't directly supported in select.epoll

    @property
    def epoll_instance(self):
        return self._epoll_object

    @property
    def eventmask(self, fd: int):
        return self._fds[fd]

    @property
    def fds(self):
        return list(self._fds.keys())

    def eventmask(self, fd: int, newmask: int):
        # the mask for an FD shouldn't ever be undefined
        # as it is set whenever an FD is added for a QlEpollObj instance
        newmask = self.eventmask() | newmask  # or with new eventmask value
        self._epoll_object.modify(fd, newmask)

    def monitor_fd(self, fd: int, eventmask: int) -> None:
        self._epoll_object.register(
            fd, eventmask
        )  # tell the epoll object to watch the fd arg, looking for events matching the eventmask
        self._fds[fd] = eventmask

    def delist_fd(self, fd: int) -> None:
        self._fds.pop(fd)
        self._epoll_object.unregister(fd)

    def close(self):
        self.epoll_instance.close()

    def is_present(self, fd: int) -> bool:
        return fd in self.fds


"""
Recursively checks each epoll instance's 'watched'
fds for an instance of epoll being watched.
If a chain of over 5 levels is detected, return
1, which will return ELOOP in ql_syscall_epoll_wait
"""


def check_epoll_depth(ql_fd_list, epolls_list, depth):
    if depth == 7:
        return 1
    new_epolls_list = []
    flag = 0
    for ent in list(epolls_list):
        watched = ent.fds
        for w in watched:
            if isinstance(ql_fd_list[w], QlEpollObj):
                new_epolls_list.append(ql_fd_list[w])
        if new_epolls_list:
            check_epoll_depth(ql_fd_list, new_epolls_list, depth + 1)
    return 0


"""
Modify an existing epoll
man 7 epoll for more details
"""


def ql_syscall_epoll_ctl(ql: Qiling, epfd: int, op: int, fd: int, event: POINTER):
    # Basic sanity checks first
    ql_event = event and ql.mem.read_ptr(event, 4)
    ql_op = ""
    epoll_obj = -1
    try:
        epoll_parent_obj = ql.os.fd[epfd]
        epoll_obj = epoll_parent_obj.epoll_instance
    except KeyError as k:
        ql.log.debug("Unable to grab epoll object, something wrong with ql.os.fd!")
        ql.log.debug(k)
        return EINVAL
    try:
        ql_op = EPOLL_OPS[op]
    except KeyError as k:
        return EINVAL  # not clear from man page, but to be safe don't support 'undefined' ops.
    """
	Qiling doesn't check process capabilities right now, so this case isn't explicitly handled yet
	EPOLLWAKEUP (since Linux 3.5)
        If EPOLLONESHOT and EPOLLET are clear and the process has the CAP_BLOCK_SUSPEND capability
	"""

    # Unclear if qiling supports a way to determine
    # if the target file descriptor is a directory
    # Check against PersistentQlFile is to ensure
    # that polling stdin, stdout, stderr is supported
    fd_obj = ql.os.fd[fd]
    if isinstance(fd_obj, ql_file) and not isinstance(
        fd_obj, PersistentQlFile
    ):  # EPERM  The target file fd does not support epoll.  This error can occur if fd refers to, for example, a regular file or a directory.
        return EPERM

    if isinstance(ql.os.fd[fd], QlEpollObj) and (op & EPOLLEXCLUSIVE):
        # EPOLLEXCLUSIVE was specified in event and fd refers to an epoll instance
        return EINVAL

    # Necessary to iterate over all possible qiling fds
    # to determine if we have a chain of more than five epolls monitoring each other
    # This may be removed in the future if the QlOsLinux class had a separate
    # field for reserved for tracking epoll objects.
    epolls_list = []
    for f in ql.os.fd:
        if isinstance(f, QlEpollObj):
            epolls_list.append(f)
    level_check = check_epoll_depth(ql.os.fd, epolls_list, 1)
    if level_check:  # more than five detected
        return ELOOP
    if epoll_obj is None or fd_obj is None:
        # epfd or fd is not a valid file descriptor.
        return EBADF
    if epfd == fd:
        return EINVAL
    if epoll_obj.fileno() == fd:
        return ELOOP  # ELOOP  ...or a nesting depth of epoll instances greater than 5.
    if ql_op == "EPOLL_CTL_ADD":
        if epoll_parent_obj.is_present(
            fd
        ):  # can't add an fd that's already being waited on
            return EEXIST  # op was EPOLL_CTL_ADD, and the supplied file descriptor fd is already registered with this epoll instance.
        epoll_parent_obj.monitor_fd(
            fd, ql_event
        )  # add to list of fds to be monitored with per-fd eventmask
        # register will actual epoll instance
        # and add eventmask accordingly
    elif ql_op == "EPOLL_CTL_DEL":
        if not epoll_parent_obj.is_present(
            fd
        ):  #  op was EPOLL_CTL_MOD or EPOLL_CTL_DEL, and fd is not registered with this epoll instance.
            return ENOENT
        epoll_parent_obj.delist_fd(fd)  # remove from fds list and do so in the
        # underlying epoll instance
    elif ql_op == "EPOLL_CTL_MOD":
        if not epoll_parent_obj.is_present(
            fd
        ):  # ENOENT op was EPOLL_CTL_MOD or EPOLL_CTL_DEL, and fd is not registered with this epoll instance
            return ENOENT
        # EINVAL op was EPOLL_CTL_MOD and events included EPOLLEXCLUSIVE.
        if op & EPOLLEXCLUSIVE and fd in epoll_obj.fds:
            return EINVAL  # EINVAL op was EPOLL_CTL_MOD and the EPOLLEXCLUSIVE flag has previously been applied to this epfd, fd pair.
        epoll_parent_obj.eventmask(ql_event)

    return 0


"""
Wait on an existing epoll for events specified
earlier. man 7 epoll_wait for more info
"""


def ql_syscall_epoll_wait(
    ql: Qiling, epfd: int, epoll_events: POINTER, maxevents: int, timeout: int
):
    if maxevents <= 0:
        return EINVAL
    # default value is 0xffffffff, but
    # this fails when passing to epoll.poll()
    if timeout == 0xFFFFFFFF:
        timeout = None

    try:
        epoll_parent_obj = ql.os.fd[epfd]
        epoll_obj = epoll_parent_obj.epoll_instance
        if not isinstance(epoll_parent_obj, QlEpollObj):
            return EINVAL
    except KeyError:
        ql.log.debug(f"FD {epfd} doesn't appear to be a valid epoll file descriptor")
        return EBADF
    try:
        ql_event = ql.mem.read_ptr(epoll_events, ql.arch.pointersize)
    except Exception:
        ql.log.debug("Can't read from epoll_events pointer")
        return EFAULT
    ready_fds = list(epoll_obj.poll(timeout, maxevents))

    # Each tuple in ready_fds consists of
    # (file descriptor, eventmask)
    # so we iterate through these to indicate which fds
    # are ready and 'why'
    ret_val = len(ready_fds)
    for i in range(0, ret_val):
        fd = ready_fds[i][0]
        interest_mask = ready_fds[i][1]
        if (
            interest_mask & EPOLLONESHOT
        ):  # no longer interested in this fd, so remove from list
            epoll_parent_obj.delist_fd(fd)

        counter = (
            ql.arch.pointersize + 4
        ) * i  # use ql.arch.pointersize to be compatible with 32-bit
        data = ql.pack32(interest_mask)  # uint32_t eventfds
        data += ql.pack(fd)  # need fd only, use pack() to handle endianness + size
        ql.mem.write(epoll_events + counter, data)
    return ret_val


"""
Use select.epoll for underlying implementation,
just as select.poll is used for emulating poll()
"""


def ql_syscall_epoll_create1(ql: Qiling, flags: int):
    if flags != select.EPOLL_CLOEXEC and flags != 0:
        return EINVAL
    ret = select.epoll(sizehint=-1, flags=flags)
    fd = ret.fileno()
    ql_obj = QlEpollObj(ret)
    ql.os.fd[fd] = ql_obj
    return fd


"""
Almost identical to above, but can't simply wrap
because of the slightly different prototype
"""


def ql_syscall_epoll_create(ql: Qiling, size: int):
    if size < 0:
        return EINVAL
    ret = select.epoll(sizehint=size, flags=0)
    fd = ret.fileno()
    ql_obj = QlEpollObj(ret)
    ql.os.fd[fd] = ql_obj
    return fd
