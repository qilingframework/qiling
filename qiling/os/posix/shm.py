#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Dict, List, Tuple, Optional


# vaguely reflects a shmid64_ds structure
class QlShmId:

    def __init__(self, key: int, uid: int, gid: int, mode: int, segsz: int) -> None:
        # ipc64_perm
        self.key = key
        self.uid = uid
        self.gid = gid
        self.mode = mode

        self.segsz = segsz

        # track the memory locations this segment is currently attached to
        self.attach: List[int] = []


class QlShm:
    def __init__(self) -> None:
        self.__shm: Dict[int, QlShmId] = {}
        self.__id: int = 0x0F000000

    def __len__(self) -> int:
        return len(self.__shm)

    def add(self, shm: QlShmId) -> int:
        shmid = self.__id
        self.__shm[shmid] = shm

        self.__id += 0x1000

        return shmid

    def remove(self, shmid: int) -> None:
        del self.__shm[shmid]

    def get_by_key(self, key: int) -> Tuple[int, Optional[QlShmId]]:
        return next(((shmid, shmobj) for shmid, shmobj in self.__shm.items() if shmobj.key == key), (-1, None))

    def get_by_id(self, shmid: int) -> Optional[QlShmId]:
        return self.__shm.get(shmid, None)

    def get_by_attaddr(self, shmaddr: int) -> Optional[QlShmId]:
        return next((shmobj for shmobj in self.__shm.values() if shmobj.attach.count(shmaddr) > 0), None)
