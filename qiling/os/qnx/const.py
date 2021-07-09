#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

# Source: openqnx lib/c/public/pthread.h

# Mutexes
NTO_SYNC_NONRECURSIVE = 0x80000000
NTO_SYNC_NOERRORCHECK = 0x40000000
NTO_SYNC_PRIOCEILING = 0x20000000
NTO_SYNC_PRIONONE = 0x10000000
NTO_SYNC_COUNTMASK = 0x00FFFFFF

NTO_SYNC_MUTEX_FREE = 0x00000000  # 0 mutexes, and old cond, sem, spin
NTO_SYNC_WAITING = 0x80000000  # Top bit used with mutexes
NTO_SYNC_OWNER_MASK = 0x7FFFFFFF  # Owner used with mutexes
NTO_SYNC_INITIALIZER = (
    0xFFFFFFFF  #   -1  count is 0=mutexes, 0(old),-5(new)=cond
)
NTO_SYNC_DESTROYED = 0xFFFFFFFE  #   -2  mutexes, cond, sem, spin
NTO_SYNC_NAMED_SEM = 0xFFFFFFFD  #   -3  sem (count is handle)
NTO_SYNC_SEM = 0xFFFFFFFC  #   -4  sem (count is value)
NTO_SYNC_COND = 0xFFFFFFFB  #   -5  cond (count is clockid)
NTO_SYNC_SPIN = 0xFFFFFFFA  #   -6  spin (count is internal)
NTO_SYNC_DEAD = (
    0xFFFFFF00  # -256  mutex (when a process dies with a mutex locked)
)

# PThread synchronization prototypes
PTHREAD_PROCESSSHARED_MASK = 1
PTHREAD_PROCESS_PRIVATE = 0
PTHREAD_PROCESS_SHARED = 1

PTHREAD_RECURSIVE_MASK = 2
PTHREAD_RECURSIVE_DISABLE = 0
PTHREAD_RECURSIVE_ENABLE = 2

PTHREAD_ERRORCHECK_MASK = 4
PTHREAD_ERRORCHECK_ENABLE = 0
PTHREAD_ERRORCHECK_DISABLE = 4

# POSIX error codes
EOK = 0
EINVAL = 22
