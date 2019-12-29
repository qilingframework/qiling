#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
# A Simple Windows Handle Simulation
class Handle:
    ID = 0xa0000000

    def __init__(self, id=None, file=None, regkey=None, thread=None, service=None):
        if id is None:
            self.id = Handle.ID
            Handle.ID += 1
        else:
            self.id = id
        self.file = file
        self.regkey = regkey
        self.thread = thread
        self.service = service

    # rewrite "="
    def __eq__(self, other):
        return self.id == other.id


class HandleManager:
    # IO
    STD_INPUT_HANDLE = Handle(id=0xfffffff6)
    STD_OUTPUT_HANDLE = Handle(id=0xfffffff5)
    STD_ERROR_HANDLE = Handle(id=0xfffffff4)

    # Register
    HKEY_CLASSES_ROOT           = Handle(id=0x80000000)
    HKEY_CURRENT_CONFIG         = Handle(id=0x80000005)
    HKEY_CURRENT_USER           = Handle(id=0x80000001)
    HKEY_CURRENT_USER_LOCAL_SETTINGS  = Handle(id=0x80000007)
    HKEY_LOCAL_MACHINE          = Handle(id=0x80000002)
    HKEY_PERFORMANCE_DATA       = Handle(id=0x80000004)
    HKEY_PERFORMANCE_NLSTEXT    = Handle(id=0x80000060)
    HKEY_PERFORMANCE_TEXT       = Handle(id=0x80000050)
    HKEY_USERS                  = Handle(id=0x80000003)

    def __init__(self):
        self.handles = {}
        self.append(HandleManager.STD_INPUT_HANDLE)
        self.append(HandleManager.STD_OUTPUT_HANDLE)
        self.append(HandleManager.STD_ERROR_HANDLE)

    def append(self, handle):
        self.handles[handle.id] = handle

    def get(self, id):
        return self.handles[id]

    def delete(self, id):
        del self.handles[id]
