#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

# Source: openqnx lib/c/public/pthread.h

# Mutexes
NTO_SYNC_NONRECURSIVE = 0x80000000
NTO_SYNC_NOERRORCHECK = 0x40000000
NTO_SYNC_PRIOCEILING  = 0x20000000
NTO_SYNC_PRIONONE     = 0x10000000
NTO_SYNC_COUNTMASK    = 0x00ffffff

NTO_SYNC_MUTEX_FREE   = 0x00000000  # 0 mutexes, and old cond, sem, spin
NTO_SYNC_WAITING      = 0x80000000  # Top bit used with mutexes
NTO_SYNC_OWNER_MASK   = 0x7fffffff  # Owner used with mutexes
NTO_SYNC_INITIALIZER  = 0xffffffff  #   -1  count is 0=mutexes, 0(old),-5(new)=cond
NTO_SYNC_DESTROYED    = 0xfffffffe  #   -2  mutexes, cond, sem, spin
NTO_SYNC_NAMED_SEM    = 0xfffffffd  #   -3  sem (count is handle)
NTO_SYNC_SEM          = 0xfffffffc  #   -4  sem (count is value)
NTO_SYNC_COND         = 0xfffffffb  #   -5  cond (count is clockid)
NTO_SYNC_SPIN         = 0xfffffffa  #   -6  spin (count is internal)
NTO_SYNC_DEAD         = 0xffffff00  # -256  mutex (when a process dies with a mutex locked)

# PThread synchronization prototypes
PTHREAD_PROCESSSHARED_MASK = 1
PTHREAD_PROCESS_PRIVATE    = 0
PTHREAD_PROCESS_SHARED     = 1

PTHREAD_RECURSIVE_MASK     = 2
PTHREAD_RECURSIVE_DISABLE  = 0
PTHREAD_RECURSIVE_ENABLE   = 2

PTHREAD_ERRORCHECK_MASK    = 4
PTHREAD_ERRORCHECK_ENABLE  = 0
PTHREAD_ERRORCHECK_DISABLE = 4

# POSIX error codes
EOK    = 0
EINVAL = 22

# Source: openqnx services/system/public/sys/neutrino.h
NTO_SIDE_CHANNEL = 0x40000000    # first side channel (2nd bit from the top)
NTO_GLOBAL_CHANNEL = 0x40000000  # global channel (2nd bit from the top)

SYSMGR_PID  = 1                  # System Manager Process ID
SYSMGR_CHID = 1                  # System Manager Channel ID
SYSMGR_COID = NTO_SIDE_CHANNEL   # System Manager Connection ID

# Source: openqnx lib/c/public/sys/iomsg.h
IO_FLAG_MASK = 0x03

# Source: openqnx lib/c/public/sys/mman.h
PAGESIZE = 0x1000

# Source: openqnx lib/c/public/sys/netmgr.h
ND_LOCAL_NODE = 0 # Node Descriptor for the Local Node

# Source: openqnx lib/c/public/sys/stat.h
S_IFMT = 0xf000
