from __future__ import annotations

import ctypes
import select

from typing import TYPE_CHECKING, Dict, KeysView, NamedTuple

from qiling.os import struct
from qiling.os.posix.const import *
from qiling.os.filestruct import PersistentQlFile, ql_file


if TYPE_CHECKING:
    from qiling import Qiling
    from qiling.arch.arch import QlArch
    from qiling.os.posix.posix import QlFileDes


class QlEpollEntry(NamedTuple):
    """A named tuple to represent an epoll entry.

    This is used to store the events mask and the data for each entry in
    the epoll instance.
    """

    events: int
    data: int


@struct.cache
def __make_epoll_event(arch: QlArch):
    """Create a structure to represent an epoll event.
    """

    Struct = struct.get_packed_struct(arch.endian)

    class epoll_event(Struct):
        _fields_ = (
            ('events', ctypes.c_uint32),
            ('data',   ctypes.c_uint64)
        )

    return epoll_event


class QlEpollObj:
    def __init__(self, epoll_object: select.epoll):
        self._epoll_object = epoll_object

        # maps fd to eventmask
        # keep track of which fds have what eventmasks,
        # since this isn't directly supported in select.epoll
        self._fds: Dict[int, QlEpollEntry] = {}

    @property
    def fds(self) -> KeysView[int]:
        return self._fds.keys()

    @property
    def epoll_instance(self) -> select.epoll:
        return self._epoll_object

    def close(self) -> None:
        self._epoll_object.close()

    def __getitem__(self, fd: int) -> QlEpollEntry:
        return self._fds[fd]

    def __setitem__(self, fd: int, entry: QlEpollEntry) -> None:
        # if fd is already being watched, modify its eventmask.
        if fd in self:
            self._epoll_object.modify(fd, entry.events)

        # otherwise, register it with the epoll object
        else:
            self._epoll_object.register(fd, entry.events)

        self._fds[fd] = entry

    def __delitem__(self, fd: int) -> None:
        """Remove an fd from the epoll instance.
        """

        self._fds.pop(fd)
        self._epoll_object.unregister(fd)

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

    if epfd == fd or fd == 0xffffffff: # latter condition was seen in testing, but should not happen in the real world
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
        check_epoll_depth(ql.os.fd)
    except RecursionError:
        return -ELOOP

    if op == EPOLL_CTL_ADD:
        # can't add an fd that's already being waited on
        if fd in epoll_parent_obj:
            return -EEXIST

        if not event:
            return -EINVAL

        # dereference the event pointer to get structure fields
        epoll_event_cls = __make_epoll_event(ql.arch)
        epoll_event = epoll_event_cls.load_from(ql.mem, event)

        # EPOLLEXCLUSIVE was specified in event and fd refers to an epoll instance
        if isinstance(fd_obj, QlEpollObj) and (epoll_event.events & EPOLLEXCLUSIVE):
            return -EINVAL

        epoll_parent_obj[fd] = QlEpollEntry(
            epoll_event.events,
            epoll_event.data
        )

    elif op == EPOLL_CTL_DEL:
        if fd not in epoll_parent_obj:
            return -ENOENT

        # remove from fds list and do so in the underlying epoll instance
        del epoll_parent_obj[fd]

    elif op == EPOLL_CTL_MOD:
        if fd not in epoll_parent_obj:
            return -ENOENT

        if not event:
            return -EINVAL

        # dereference the event pointer to get structure fields
        epoll_event_cls = __make_epoll_event(ql.arch)
        epoll_event = epoll_event_cls.load_from(ql.mem, event)

        # EPOLLEXCLUSIVE cannot be set on MOD operation, only on ADD
        if epoll_event.events & EPOLLEXCLUSIVE:
            return -EINVAL

        epoll_parent_obj[fd] = QlEpollEntry(
            epoll_event.events,
            epoll_event.data
        )

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

    epoll_event_cls = __make_epoll_event(ql.arch)

    # Each tuple in ready_fds consists of (file descriptor, eventmask) so we iterate
    # through these to indicate which fds are ready and 'why'
    #
    # FIXME: emulated system fds are not the same as hosted system fds
    for i, (fd, events) in enumerate(ready_fds):
        entry = epoll_parent_obj[fd]
        epoll_event = epoll_event_cls(events, entry.data)

        offset = epoll_event_cls.sizeof() * i
        ql.mem.write(epoll_events + offset, bytes(epoll_event))

        # if no longer interested in this fd, remove from list
        if events & EPOLLONESHOT:
            del epoll_parent_obj[fd]

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
