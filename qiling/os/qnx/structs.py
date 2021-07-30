#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#
import ctypes

from qiling.os.qnx.const import *

class MemoryStructure(ctypes.Structure):
    def __init__(self, ql, base):
        super().__init__()
        self.ql = ql
        self.base = base

    def updateToMem(self):
        self.ql.mem.write(self.base, bytes(self))

    def loadFromMem(self):
        data = self.ql.mem.read(self.base, ctypes.sizeof(self))
        newObj = type(self).from_buffer(data)
        newObj.ql = self.ql
        newObj.base = self.base
        return newObj

    def dump(self):
        for field in self._fields_:
            if isinstance(getattr(self, field[0]), POINTER32):
                self.ql.log.info("%s: 0x%x" % (field[0], getattr(self, field[0]).value))
            elif isinstance(getattr(self, field[0]), int):
                self.ql.log.info("%s: %d" % (field[0], getattr(self, field[0])))
            elif isinstance(getattr(self, field[0]), bytes):
                self.ql.log.info("%s: %s" % (field[0], getattr(self, field[0]).decode()))


class POINTER32(ctypes.Structure):
    _fields_ = [("value", ctypes.c_uint32)]

# Source: openqnx services/system/ker/kermacros.h
# define SYNC_OWNER_BITS(pid,tid)  ((((pid) << 16) | (tid) + 1) & ~_NTO_SYNC_WAITING)
# define SYNC_OWNER(thp)           SYNC_OWNER_BITS((thp)->process->pid, (thp)->tid)
# define SYNC_PINDEX(owner)        PINDEX(((owner) & ~_NTO_SYNC_WAITING) >> 16)
# define SYNC_TID(owner)           (((owner) & 0xffff) - 1)


# Source: openqnx lib/c/public/sys/target_nto.h
# owner
# -1    Static initalized mutex which is auto created on SyncWait
# -2    Destroyed mutex
# -3    Named semaphore (the count is used as an fd)
class _sync(MemoryStructure):
    _fields_ = (
        ("_count", ctypes.c_int32),         # 0  (0x00) int __count;
        ("_owner", ctypes.c_uint32),        # 4  (0x04) unsigned __owner;
    )

    def __init__(self, ql, base):
        super().__init__(ql, base)

# Source: openqnx lib/c/public/sys/target_nto.h
class _sync_attr(MemoryStructure):
    _fields_ = (
        ("_protocol", ctypes.c_int32),      # 0  (0x00) int __protocol;
        ("_flags", ctypes.c_int32),         # 4  (0x04) int __flags;
        ("_prioceiling", ctypes.c_int32),   # 8  (0x08) int __prioceiling;
        ("_clockid", ctypes.c_int32),       # 12 (0x0c) int __clockid;
        ("_reserved1", ctypes.c_int32),     # 16 (0x10) int __reserved[0];        
        ("_reserved2", ctypes.c_int32),     # 16 (0x14) int __reserved[0];
        ("_reserved3", ctypes.c_int32),     # 16 (0x18) int __reserved[0];
        ("_reserved4", ctypes.c_int32),     # 16 (0x1c) int __reserved[0];
    )

    def __init__(self, ql, base):
        super().__init__(ql, base)

# Source: openqnx lib/c/public/sys/target_nto.h
# Thread local storage. This data is at the top of each threads stack.
class _thread_local_storage(MemoryStructure):
    _fields_ = (
        ("_exitfunc", POINTER32),           # 0  (0x00) void (*__exitfunc)(void *);
        ("_arg", POINTER32),                # 4  (0x04) void *__arg;
        ("_errptr", POINTER32),             # 8  (0x08) int *__errptr;
        ("_errval", ctypes.c_int32),        # 12 (0x0c) int __errval;
        ("_flags", ctypes.c_uint32),        # 16 (0x10) unsigned __flags;
        ("_pid", ctypes.c_int32),           # 20 (0x14) int __pid;
        ("_tid", ctypes.c_int32),           # 24 (0x18) int __tid;
        ("_owner", ctypes.c_uint32),        # 28 (0x1c) unsigned __owner;
        ("_stackaddr", POINTER32),          # 32 (0x20) void *__stackaddr;
        ("_reserved1", ctypes.c_uint32),    # 36 (0x24) unsigned __reserved1;
        ("_numkeys", ctypes.c_uint32),      # 40 (0x28) unsigned __numkeys;
        ("_keydata", POINTER32),            # 44 (0x2c) void **__keydata;   // Indexed by pthread_key_t
        ("_cleanup", POINTER32),            # 48 (0x30) void *__cleanup;
        ("_fpuemu_data", POINTER32),        # 52 (0x34) void *__fpuemu_data;
        ("_reserved2", POINTER32),          # 56 (0x38) void *__reserved2[0];
        ("_reserved3", POINTER32),          # 60 (0x3c) void *__reserved2[1];
    )

    def __init__(self, ql, base):
        super().__init__(ql, base)

    @property
    def pid(self):
        return self._pid

    @pid.setter
    def pid(self, value):
        self._pid = value
        self.updateOwner()

    @property
    def tid(self):
        return self._tid

    @tid.setter
    def tid(self, value):
        self._tid = value
        self.updateOwner()

    def updateOwner(self):
        self._owner = ((self._pid << 16) | self._tid) & ~NTO_SYNC_WAITING

__all__ = ['_sync', '_sync_attr', '_thread_local_storage']