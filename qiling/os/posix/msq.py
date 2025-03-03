#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Dict, Tuple, Optional
from collections import deque

from qiling.os.posix.const import MSGMNB


class QlMsgBuf:
    def __init__(self, mtype: int, mtext: bytes) -> None:
        self.mtype = mtype
        self.mtext = mtext


# vaguely reflects a msqid64_ds structure
class QlMsqId:
    def __init__(self, key: int, uid: int, gid: int, mode: int) -> None:
        # ipc64_perm
        self.key = key
        self.uid = uid
        self.gid = gid
        self.mode = mode

        self.queue = deque(maxlen=MSGMNB)

    def __len__(self):
        return len(self.queue)


class QlMsq:
    def __init__(self) -> None:
        self.__msq: Dict[int, QlMsqId] = {}
        self.__id: int = 0x0F000000

    def __len__(self) -> int:
        return len(self.__msq)

    def add(self, msq: QlMsqId) -> int:
        msqid = self.__id
        self.__msq[msqid] = msq

        self.__id += 0x1000

        return msqid

    def remove(self, msqid: int) -> None:
        del self.__msq[msqid]

    def get_by_key(self, key: int) -> Tuple[int, Optional[QlMsqId]]:
        return next(((msqid, msqobj) for msqid, msqobj in self.__msq.items() if msqobj.key == key), (-1, None))

    def get_by_id(self, msqid: int) -> Optional[QlMsqId]:
        return self.__msq.get(msqid, None)
