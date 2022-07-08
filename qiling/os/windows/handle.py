#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#
# A Simple Windows Handle Simulation

from typing import Any, MutableMapping, Optional

from qiling.os.windows.const import STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE

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
    STDIN  = Handle(id=STD_INPUT_HANDLE)
    STDOUT = Handle(id=STD_OUTPUT_HANDLE)
    STDERR = Handle(id=STD_ERROR_HANDLE)

    def __init__(self):
        self.handles: MutableMapping[int, Handle] = {}

        # standard io streams
        self.append(HandleManager.STDIN)
        self.append(HandleManager.STDOUT)
        self.append(HandleManager.STDERR)

        # registry hives
        self.append(Handle(id=0x80000000, name='HKEY_CLASSES_ROOT'))
        self.append(Handle(id=0x80000001, name='HKEY_CURRENT_USER'))
        self.append(Handle(id=0x80000002, name='HKEY_LOCAL_MACHINE'))
        self.append(Handle(id=0x80000003, name='HKEY_USERS'))
        self.append(Handle(id=0x80000004, name='HKEY_PERFORMANCE_DATA'))
        self.append(Handle(id=0x80000005, name='HKEY_CURRENT_CONFIG'))
        self.append(Handle(id=0x80000007, name='HKEY_CURRENT_USER_LOCAL_SETTINGS'))
        self.append(Handle(id=0x80000060, name='HKEY_PERFORMANCE_NLSTEXT'))
        self.append(Handle(id=0x80000050, name='HKEY_PERFORMANCE_TEXT'))

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
