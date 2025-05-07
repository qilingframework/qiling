from __future__ import annotations

import select

from typing import TYPE_CHECKING, Dict, KeysView

from qiling.os.posix.const import *
from qiling.os.filestruct import PersistentQlFile, ql_file


if TYPE_CHECKING:
    from qiling import Qiling
    from qiling.os.posix.posix import QlFileDes

class QlEpollObj:
    def __init__(self, epoll_object: select.epoll):
        self._epoll_object = epoll_object

        # maps fd to eventmask
        # keep track of which fds have what eventmasks,
        # since this isn't directly supported in select.epoll
        self._fds: Dict[int, int] = {}

    @property
    def fds(self) -> KeysView[int]:
        return self._fds.keys()

    @property
    def epoll_instance(self) -> select.epoll:
        return self._epoll_object

    def get_eventmask(self, fd: int) -> int:
        return self._fds[fd]

    def set_eventmask(self, fd: int, newmask: int):
        # the mask for an FD shouldn't ever be undefined
        # as it is set whenever an FD is added for a QlEpollObj instance

        newmask = self.get_eventmask(fd) | newmask

        self._epoll_object.modify(fd, newmask)
        self._fds[fd] = newmask

    def monitor_fd(self, fd: int, eventmask: int) -> None:
        # tell the epoll object to watch the fd arg, looking for events matching the eventmask
        self._epoll_object.register(fd, eventmask)
        self._fds[fd] = eventmask

    def delist_fd(self, fd: int) -> None:
        self._fds.pop(fd)
        self._epoll_object.unregister(fd)

    def close(self) -> None:
        self._epoll_object.close()


    def __contains__(self, fd: int) -> bool:
        """Test whether a specific fd is already being watched by this epoll instance.
        """


        return fd in self.fds


def check_epoll_depth(ql_fd_list: QlFileDes) -> None:
    """Recursively check each epoll instance's 'watched' fds for an instance of
    epoll being watched. If a chain of over 5 levels is detected, raise an exception
    """

    def __visit_obj(obj: QlEpollObj, depth: int):
        if depth >= 5:
            raise RecursionError

        for fd in obj.fds:
            if isinstance(ql_fd_list[fd], QlEpollObj):
                __visit_obj(obj, depth + 1)

    for obj in ql_fd_list:
        if isinstance(obj, QlEpollObj):
            __visit_obj(obj, 1)



def ql_syscall_epoll_ctl(ql: Qiling, epfd: int, op: int, fd: int, event: int):
    """Modify an existing epoll.
    """

    # not clear from man page, but to be safe don't support 'undefined' ops.
    if op not in (EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD):
        return -EINVAL

    if epfd == fd:
        return -EINVAL

    if epfd not in range(NR_OPEN):
        return -EBADF

    epoll_parent_obj = ql.os.fd[epfd]

    if not isinstance(epoll_parent_obj, QlEpollObj):
        return -EINVAL

    epoll_obj = epoll_parent_obj.epoll_instance

    if epoll_obj is None:
        return -EBADF

    if epoll_obj.fileno() == fd:
        return -ELOOP

	# Qiling doesn't check process capabilities right now, so this case isn't explicitly handled yet
	# EPOLLWAKEUP (since Linux 3.5)
    #     If EPOLLONESHOT and EPOLLET are clear and the process has the CAP_BLOCK_SUSPEND capability

    fd_obj = ql.os.fd[fd]

    if fd_obj is None:
        return -EBADF

    # TODO: not sure if qiling supports a way to determine if the target file descriptor is a
    # directory. Here, check against PersistentQlFile is to ensure that polling stdin, stdout,
    # stderr is supported

    # The target file fd does not support epoll. This error can occur if fd refers to, for
    # example, a regular file or a directory.
    if isinstance(fd_obj, ql_file) and not isinstance(fd_obj, PersistentQlFile):
        return -EPERM



    # EPOLLEXCLUSIVE was specified in event and fd refers to an epoll instance
    if isinstance(fd_obj, QlEpollObj) and (op & EPOLLEXCLUSIVE):
        return -EINVAL

    # Necessary to iterate over all possible qiling fds to determine if we have a chain of more
    # than five epolls monitoring each other This may be removed in the future if the QlOsLinux
    # class had a separate field for reserved for tracking epoll objects.
    epolls_list = [fobj for fobj in ql.os.fd if isinstance(fobj, QlEpollObj)]

    try:
        # Necessary to iterate over all possible qiling fds to determine if we have a chain of more
        # than five epolls monitoring each other This may be removed in the future if the QlOsLinux
        # class had a separate field reserved for tracking epoll objects.
        check_epoll_depth(ql.os.fd)
    except RecursionError:
        return -ELOOP

    if op == EPOLL_CTL_ADD:
        # can't add an fd that's already being waited on
        if fd in epoll_parent_obj:
            return -EEXIST

        if not event:
            return -EINVAL

        event_ptr = ql.mem.read_ptr(event)
        events = ql.mem.read_ptr(event_ptr, 4)

        # EPOLLEXCLUSIVE was specified in event and fd refers to an epoll instance
        if isinstance(fd_obj, QlEpollObj) and (op & EPOLLEXCLUSIVE):
            return -EINVAL

        # add to list of fds to be monitored with per-fd eventmask register will actual epoll
        # instance and add eventmask accordingly
        epoll_parent_obj.monitor_fd(fd, events)

    elif op == EPOLL_CTL_DEL:
        if fd not in epoll_parent_obj:
            return -ENOENT

        # remove from fds list and do so in the underlying epoll instance
        epoll_parent_obj.delist_fd(fd)

    elif op == EPOLL_CTL_MOD:
        if fd not in epoll_parent_obj:
            return -ENOENT

        if not event:
            return -EINVAL

        event_ptr = ql.mem.read_ptr(event)
        events = ql.mem.read_ptr(event_ptr, 4)

        # EPOLLEXCLUSIVE cannot be set on MOD operation, only on ADD
        if events & EPOLLEXCLUSIVE:
            return -EINVAL

        epoll_parent_obj.set_eventmask(fd, events)

    return 0


def ql_syscall_epoll_wait(ql: Qiling, epfd: int, epoll_events: int, maxevents: int, timeout: int):
    """Wait on an existing epoll for specific events.
    """

    if maxevents <= 0:
        return -EINVAL

    # default value is 0xffffffff, but this fails when passing to epoll.poll()
    if timeout == 0xFFFFFFFF:
        timeout = None

    if epfd not in range(NR_OPEN):
        return -EBADF

    epoll_parent_obj = ql.os.fd[epfd]

    if not isinstance(epoll_parent_obj, QlEpollObj):
        return -EINVAL

    epoll_obj = epoll_parent_obj.epoll_instance

    if epoll_obj is None:
        return -EBADF

    ready_fds = epoll_obj.poll(timeout, maxevents)

    # Each tuple in ready_fds consists of (file descriptor, eventmask) so we iterate
    # through these to indicate which fds are ready and 'why'

    for i, (fd, events) in enumerate(ready_fds):
        # if no longer interested in this fd, remove from list
        if events & EPOLLONESHOT:
            epoll_parent_obj.delist_fd(fd)

        # FIXME: the data packed after events should be the one passed on epoll_ctl
        # for that specific fd. currently this does not align with the spec
        data = ql.pack32(events) + ql.pack64(fd)
        offset = len(data) * i

        ql.mem.write(epoll_events + offset, data)

    return len(ready_fds)


def __epoll_create(ql: Qiling, sizehint: int, flags: int) -> int:
    # Use select.epoll for underlying implementation, just as select.poll is
    # used for emulating poll()

    ret = select.epoll(sizehint, flags)

    fd = ret.fileno()
    ql.os.fd[fd] = QlEpollObj(ret)

    return fd


def ql_syscall_epoll_create1(ql: Qiling, flags: int):
    if flags != select.EPOLL_CLOEXEC and flags != 0:
        return -EINVAL

    return __epoll_create(ql, -1, flags)


def ql_syscall_epoll_create(ql: Qiling, size: int):
    if size < 0:
        return -EINVAL

    return __epoll_create(ql, size, 0)
