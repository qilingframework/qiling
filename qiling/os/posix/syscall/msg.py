from typing import Optional
from qiling import Qiling
from qiling.os.posix.const import *
from qiling.os.posix.msq import QlMsqId, QlMsgBuf


def __find_msg(msq: QlMsqId, msgtyp: int, msgflg: int) -> Optional[QlMsgBuf]:
    # peek at a specific queue item
    if msgflg & MSG_COPY:
        return msq.queue[msgtyp] if msgtyp < len(msq.queue) else None

    if msgtyp == 0:
        predicate = lambda msg: True

    elif msgtyp > 0:
        if msgflg & MSG_EXCEPT:
            predicate = lambda msg: msg.mtype != msgtyp
        else:
            predicate = lambda msg: msg.mtype == msgtyp

    elif msgtyp < 0:
        predicate = lambda msg: msg.mtype <= -msgtyp

    return next((msg for msg in msq.queue if predicate(msg)), None)


def __perms(ql: Qiling, msq: QlMsqId, flag: int) -> int:
    """
    # see: https://elixir.bootlin.com/linux/v5.19.17/source/ipc/util.c#L553
    # check whether the user has permissions to access this message queue
    # FIXME: should probably also use cuid and (c)gid, but we don't support it yet
    # TODO: other ipc mechanisms like shm can also reuse this
    """

    request_mode = (flag >> 6) | (flag >> 3) | flag
    granted_mode = msq.mode

    if ql.os.uid == msq.uid:
        granted_mode >>= 6

    # is there some bit set in requested_mode but not in granted_mode?
    if request_mode & ~granted_mode & 0o007:
        return -1  # EACCES

    return 0


def ql_syscall_msgget(ql: Qiling, key: int, msgflg: int):
    def __create_msq(key: int, flags: int) -> int:
        """Create a new message queue for the specified key.

        Returns: msqid of the newly created message queue, -1 if an error has occurred
        """

        if len(ql.os.msq) >= MSGMNI:
            return -1  # ENOSPC

        mode = flags & ((1 << 9) - 1)

        msqid = ql.os.msq.add(QlMsqId(key, ql.os.uid, ql.os.gid, mode))

        ql.log.debug(f'created a new msg queue: key = {key:#x}, mode = 0{mode:o}. assigned id: {msqid:#x}')

        return msqid

    # create new message queue
    if key == IPC_PRIVATE:
        msqid = __create_msq(key, msgflg)

    else:
        msqid, msq = ql.os.msq.get_by_key(key)

        # a message queue with the specified key does not exist
        if msq is None:
            # the user asked to create a new one?
            if msgflg & IPC_CREAT:
                msqid = __create_msq(key, msgflg)

            else:
                return -1  # ENOENT

        # a message queue with the specified key exists
        else:
            # the user asked to create a new one?
            if msgflg & (IPC_CREAT | IPC_EXCL):
                return -1  # EEXIST

            if __perms(ql, msq, msgflg):
                return -1  # EACCES

    return msqid


def ql_syscall_msgsnd(ql: Qiling, msqid: int, msgp: int, msgsz: int, msgflg: int):
    msq = ql.os.msq.get_by_id(msqid)

    if msq is None:
        return -1  # EINVAL

    # Check if the user has write permissions for the message queue
    if __perms(ql, msq, 0o222):  # S_IWUGO
        return -1  # EACCES

    msg_type = ql.mem.read_ptr(msgp)
    msg_text = ql.mem.read(msgp + ql.arch.pointersize, msgsz)

    while True:
        if len(msq.queue) < msq.queue.maxlen:
            break

        if msgflg & IPC_NOWAIT:
            return -1  # EAGAIN

    msq.queue.append(QlMsgBuf(msg_type, bytes(msg_text)))

    return 0  # Success


def ql_syscall_msgrcv(ql: Qiling, msqid: int, msgp: int, msgsz: int, msgtyp: int, msgflg: int):
    msq = ql.os.msq.get_by_id(msqid)

    if msq is None:
        return -1  # EINVAL

    if msgflg & MSG_COPY:
        if msgflg & MSG_EXCEPT or not (msgflg & IPC_NOWAIT):
            return -1  # EINVAL

    # Check if the user has read permissions for the message queue
    if __perms(ql, msq, 0o444):  # S_IRUGO
        return -1  # EACCES

    while True:
        msg = __find_msg(msq, msgtyp, msgflg)

        if msg is not None:
            break

        if msgflg & MSG_COPY:
            return -1  # ENOMSG

        if msgflg & IPC_NOWAIT:
            return -1  # ENOMSG

    if not (msgflg & MSG_COPY):
        msq.queue.remove(msg)

    if msgsz < len(msg.mtext):
        if not (msgflg & MSG_NOERROR):
            return -1  # E2BIG
        else:
            sz = msgsz
    else:
        sz = len(msg.mtext)

    ql.mem.write_ptr(msgp, msg.mtype)
    ql.mem.write(msgp + ql.arch.pointersize, msg.mtext[:sz])

    return sz  # Success


__all__ = [
    'ql_syscall_msgget',
    'ql_syscall_msgsnd',
    'ql_syscall_msgrcv'
]
