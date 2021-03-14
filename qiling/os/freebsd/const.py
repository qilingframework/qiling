#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

# From FreeBSD /sys/sys/sysctl.h

#
# Top-level identifiers
#

# Note(lazymio): CTL_SYSCTL doesn't exist in linux kernel!

CTL_SYSCTL   = 0 # "magic" numbers
CTL_KERN     = 1 # "high kernel": proc, limits
CTL_VM       = 2 # virtual memory
CTL_VFS      = 3 # filesystem, mount type is next
CTL_NET      = 4 # network, see socket.h
CTL_DEBUG    = 5 # debugging parameters
CTL_HW       = 6 # generic cpu/io
CTL_MACHDEP  = 7 # machine dependent
CTL_USER     = 8 # user-level
CTL_P1003_1B = 9 # POSIX 1003.1B

#
# CTL_SYSCTL identifiers
#

CTL_SYSCTL_DEBUG      = 0 # printf all nodes
CTL_SYSCTL_NAME       = 1 # string name of OID
CTL_SYSCTL_NEXT       = 2 # next OID, honoring CTLFLAG_SKIP
CTL_SYSCTL_NAME2OID   = 3 # int array of name
CTL_SYSCTL_OIDFMT     = 4 # OID's kind and format
CTL_SYSCTL_OIDDESCR   = 5 # OID's description
CTL_SYSCTL_OIDLABEL   = 6 # aggregation label
CTL_SYSCTL_NEXTNOSKIP = 7 # next OID, ignoring CTLFLAG_SKIP

#
# CTL_KERN identifiers
#

KERN_OSTYPE          = 1  # string: system version
KERN_OSRELEASE       = 2  # string: system release
KERN_OSREV           = 3  # int: system revision
KERN_VERSION         = 4  # string: compile time info
KERN_MAXVNODES       = 5  # int: max vnodes
KERN_MAXPROC         = 6  # int: max processes
KERN_MAXFILES        = 7  # int: max open files
KERN_ARGMAX          = 8  # int: max arguments to exec
KERN_SECURELVL       = 9  # int: system security level
KERN_HOSTNAME        = 10 # string: hostname
KERN_HOSTID          = 11 # int: host identifier
KERN_CLOCKRATE       = 12 # struct: struct clockrate
KERN_VNODE           = 13 # struct: vnode structures
KERN_PROC            = 14 # struct: process entries
KERN_FILE            = 15 # struct: file entries
KERN_PROF            = 16 # node: kernel profiling info
KERN_POSIX1          = 17 # int: POSIX.1 version
KERN_NGROUPS         = 18 # int: # of supplemental group ids
KERN_JOB_CONTROL     = 19 # int: is job control available
KERN_SAVED_IDS       = 20 # int: saved set-user/group-ID
KERN_BOOTTIME        = 21 # struct: time kernel was booted
KERN_NISDOMAINNAME   = 22 # string: YP domain name
KERN_UPDATEINTERVAL  = 23 # int: update process sleep time
KERN_OSRELDATE       = 24 # int: kernel release date
KERN_NTP_PLL         = 25 # node: NTP PLL control
KERN_BOOTFILE        = 26 # string: name of booted kernel
KERN_MAXFILESPERPROC = 27 # int: max open files per proc
KERN_MAXPROCPERUID   = 28 # int: max processes per uid
KERN_DUMPDEV         = 29 # struct cdev *: device to dump on
KERN_IPC             = 30 # node: anything related to IPC
KERN_DUMMY           = 31 # unused
KERN_PS_STRINGS      = 32 # int: address of PS_STRINGS
KERN_USRSTACK        = 33 # int: address of USRSTACK
KERN_LOGSIGEXIT      = 34 # int: do we log sigexit procs?
KERN_IOV_MAX         = 35 # int: value of UIO_MAXIOV
KERN_HOSTUUID        = 36 # string: host UUID identifier
KERN_ARND            = 37 # int: from arc4rand()
KERN_MAXPHYS         = 38 # int: MAXPHYS value

#
# KERN_PROC subtypes
#

KERN_PROC_ALL         = 0     # everything
KERN_PROC_PID         = 1     # by process id
KERN_PROC_PGRP        = 2     # by process group id
KERN_PROC_SESSION     = 3     # by session of pid
KERN_PROC_TTY         = 4     # by controlling tty
KERN_PROC_UID         = 5     # by effective uid
KERN_PROC_RUID        = 6     # by real uid
KERN_PROC_ARGS        = 7     # get/set arguments/proctitle
KERN_PROC_PROC        = 8     # only return procs
KERN_PROC_SV_NAME     = 9     # get syscall vector name
KERN_PROC_RGID        = 10    # by real group id
KERN_PROC_GID         = 11    # by effective group id
KERN_PROC_PATHNAME    = 12    # path to executable
KERN_PROC_OVMMAP      = 13    # Old VM map entries for process
KERN_PROC_OFILEDESC   = 14    # Old file descriptors for process
KERN_PROC_KSTACK      = 15    # Kernel stacks for process
KERN_PROC_INC_THREAD  = 0x10  # modifier for pid, pgrp, tty,uid, ruid, gid, rgid and proc This effectively uses 16-31   
KERN_PROC_VMMAP       = 32    # VM map entries for process
KERN_PROC_FILEDESC    = 33    # File descriptors for process
KERN_PROC_GROUPS      = 34    # process groups
KERN_PROC_ENV         = 35    # get environment
KERN_PROC_AUXV        = 36    # get ELF auxiliary vector
KERN_PROC_RLIMIT      = 37    # process resource limits
KERN_PROC_PS_STRINGS  = 38    # get ps_strings location
KERN_PROC_UMASK       = 39    # process umask
KERN_PROC_OSREL       = 40    # osreldate for process binary
KERN_PROC_SIGTRAMP    = 41    # signal trampoline location
KERN_PROC_CWD         = 42    # process current working directory
KERN_PROC_NFDS        = 43    # number of open file descriptors

#
# KERN_IPC identifiers
#

KIPC_MAXSOCKBUF      = 1  # int: max size of a socket buffer
KIPC_SOCKBUF_WASTE   = 2  # int: wastage factor in sockbuf
KIPC_SOMAXCONN       = 3  # int: max length of connection q
KIPC_MAX_LINKHDR     = 4  # int: max length of link header
KIPC_MAX_PROTOHDR    = 5  # int: max length of network header
KIPC_MAX_HDR         = 6  # int: max total length of headers
KIPC_MAX_DATALEN     = 7  # int: max length of data?

#
# CTL_HW identifiers
#

HW_MACHINE      = 1    # string: machine class
HW_MODEL        = 2    # string: specific machine model
HW_NCPU         = 3    # int: number of cpus
HW_BYTEORDER    = 4    # int: machine byte order
HW_PHYSMEM      = 5    # int: total memory
HW_USERMEM      = 6    # int: non-kernel memory
HW_PAGESIZE     = 7    # int: software page size
HW_DISKNAMES    = 8    # strings: disk drive names
HW_DISKSTATS    = 9    # struct: diskstats[]
HW_FLOATINGPT   = 10   # int: has HW floating point?
HW_MACHINE_ARCH = 11   # string: machine architecture
HW_REALMEM      = 12   # int: 'real' memory

#
# CTL_USER definitions
#

USER_CS_PATH            = 1   # string: _CS_PATH
USER_BC_BASE_MAX        = 2   # int: BC_BASE_MAX
USER_BC_DIM_MAX         = 3   # int: BC_DIM_MAX
USER_BC_SCALE_MAX       = 4   # int: BC_SCALE_MAX
USER_BC_STRING_MAX      = 5   # int: BC_STRING_MAX
USER_COLL_WEIGHTS_MAX   = 6   # int: COLL_WEIGHTS_MAX
USER_EXPR_NEST_MAX      = 7   # int: EXPR_NEST_MAX
USER_LINE_MAX           = 8   # int: LINE_MAX
USER_RE_DUP_MAX         = 9   # int: RE_DUP_MAX
USER_POSIX2_VERSION     = 10  # int: POSIX2_VERSION
USER_POSIX2_C_BIND      = 11  # int: POSIX2_C_BIND
USER_POSIX2_C_DEV       = 12  # int: POSIX2_C_DEV
USER_POSIX2_CHAR_TERM   = 13  # int: POSIX2_CHAR_TERM
USER_POSIX2_FORT_DEV    = 14  # int: POSIX2_FORT_DEV
USER_POSIX2_FORT_RUN    = 15  # int: POSIX2_FORT_RUN
USER_POSIX2_LOCALEDEF   = 16  # int: POSIX2_LOCALEDEF
USER_POSIX2_SW_DEV      = 17  # int: POSIX2_SW_DEV
USER_POSIX2_UPE         = 18  # int: POSIX2_UPE
USER_STREAM_MAX         = 19  # int: POSIX2_STREAM_MAX
USER_TZNAME_MAX         = 20  # int: POSIX2_TZNAME_MAX

CTL_P1003_1B_ASYNCHRONOUS_IO       = 1  # boolean
CTL_P1003_1B_MAPPED_FILES          = 2  # boolean
CTL_P1003_1B_MEMLOCK               = 3  # boolean
CTL_P1003_1B_MEMLOCK_RANGE         = 4  # boolean
CTL_P1003_1B_MEMORY_PROTECTION     = 5  # boolean
CTL_P1003_1B_MESSAGE_PASSING       = 6  # boolean
CTL_P1003_1B_PRIORITIZED_IO        = 7  # boolean
CTL_P1003_1B_PRIORITY_SCHEDULING   = 8  # boolean
CTL_P1003_1B_REALTIME_SIGNALS      = 9  # boolean
CTL_P1003_1B_SEMAPHORES            = 10 # boolean
CTL_P1003_1B_FSYNC                 = 11 # boolean
CTL_P1003_1B_SHARED_MEMORY_OBJECTS = 12 # boolean
CTL_P1003_1B_SYNCHRONIZED_IO       = 13 # boolean
CTL_P1003_1B_TIMERS                = 14 # boolean
CTL_P1003_1B_AIO_LISTIO_MAX        = 15 # int
CTL_P1003_1B_AIO_MAX               = 16 # int
CTL_P1003_1B_AIO_PRIO_DELTA_MAX    = 17 # int
CTL_P1003_1B_DELAYTIMER_MAX        = 18 # int
CTL_P1003_1B_MQ_OPEN_MAX           = 19 # int
CTL_P1003_1B_PAGESIZE              = 20 # int
CTL_P1003_1B_RTSIG_MAX             = 21 # int
CTL_P1003_1B_SEM_NSEMS_MAX         = 22 # int
CTL_P1003_1B_SEM_VALUE_MAX         = 23 # int
CTL_P1003_1B_SIGQUEUE_MAX          = 24 # int
CTL_P1003_1B_TIMER_MAX             = 25 # int
CTL_P1003_1B_MAXID                 = 26