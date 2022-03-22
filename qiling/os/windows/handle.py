#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#
# A Simple Windows Handle Simulation

from typing import Any, MutableMapping, Optional

class Handle:
    ID = 0xa0000000

    def __init__(self, id: Optional[int] = None, obj: Any = None, name: Optional[str] = None, permissions: Optional[int] = None):
        if id is None:
            id = Handle.ID
            Handle.ID += 1

        self.id = id
        self.obj = obj
        self.name = name
        self.permissions = permissions

    # overload "=="
    def __eq__(self, other: 'Handle'):
        return self.id == other.id


class HandleManager:
    # IO
    STD_INPUT_HANDLE  = Handle(id=0xfffffff6)
    STD_OUTPUT_HANDLE = Handle(id=0xfffffff5)
    STD_ERROR_HANDLE  = Handle(id=0xfffffff4)

    # Register
    HKEY_CLASSES_ROOT        = Handle(id=0x80000000)
    HKEY_CURRENT_CONFIG      = Handle(id=0x80000005)
    HKEY_CURRENT_USER        = Handle(id=0x80000001)
    HKEY_CURRENT_USER_LOCAL_SETTINGS = Handle(id=0x80000007)
    HKEY_LOCAL_MACHINE       = Handle(id=0x80000002)
    HKEY_PERFORMANCE_DATA    = Handle(id=0x80000004)
    HKEY_PERFORMANCE_NLSTEXT = Handle(id=0x80000060)
    HKEY_PERFORMANCE_TEXT    = Handle(id=0x80000050)
    HKEY_USERS               = Handle(id=0x80000003)

    def __init__(self):
        self.handles: MutableMapping[int, Handle] = {}

        self.append(HandleManager.STD_INPUT_HANDLE)
        self.append(HandleManager.STD_OUTPUT_HANDLE)
        self.append(HandleManager.STD_ERROR_HANDLE)

    def append(self, handle: Handle) -> None:
        self.handles[handle.id] = handle

    def get(self, id: int) -> Optional[Handle]:
        return self.handles.get(id, None)

    def delete(self, id: int) -> None:
        key = self.get(id)

        if key is not None:
            del self.handles[id]

    def search(self, name: str) -> Optional[Handle]:
        return next((handle for handle in self.handles.values() if handle.name == name), None)

    def search_by_obj(self, obj: Any) -> Optional[Handle]:
        return next((handle for handle in self.handles.values() if handle.obj == obj), None)
