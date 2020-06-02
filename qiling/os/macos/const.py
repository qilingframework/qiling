#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

# basic values
PAGE_SIZE                   = 0x1000
VMMAP_PAGE_SIZE             = 0x100000
MAX_FD_SIZE					= 0xFF
MAX_PATH_SIZE               = 0x800

# GS
MSR_KERNEL_GS_BASE          = 0xc0000102

# kernel flags
KERN_SUCCESS                = 0
KERN_INVALID_ADDRESS        = 1
KERN_PROTECTION_FAILURE     = 2
KERN_NO_SPACE               = 3
KERN_INVALID_ARGUMENT       = 4
KERN_FAILURE                = 5
KERN_RESOURCE_SHORTAGE      = 6
KERN_NOT_RECEIVER           = 7
KERN_NO_ACCESS              = 8
KERN_MEMORY_FAILURE         = 9
KERN_MEMORY_ERROR           = 10
KERN_ALREADY_IN_SET         = 11
KERN_NOT_IN_SET             = 12
KERN_NAME_EXISTS            = 13
KERN_ABORTED                = 14
KERN_INVALID_NAME           = 15
KERN_INVALID_TASK           = 16
KERN_INVALID_RIGHT          = 17
KERN_INVALID_VALUE          = 18
KERN_UREFS_OVERFLOW         = 19
KERN_INVALID_CAPABILITY     = 20
KERN_RIGHT_EXISTS           = 21
KERN_INVALID_HOST           = 22
KERN_MEMORY_PRESENT         = 23
KERN_MEMORY_DATA_MOVED      = 24
KERN_MEMORY_RESTART_COPY    = 25
KERN_INVALID_PROCESSOR_SET  = 26
KERN_POLICY_LIMIT           = 27
KERN_INVALID_POLICY         = 28
KERN_INVALID_OBJECT         = 29
KERN_ALREADY_WAITING        = 30
KERN_DEFAULT_SET            = 31
KERN_EXCEPTION_PROTECTED    = 32
KERN_INVALID_LEDGER         = 33
KERN_INVALID_MEMORY_CONTROL = 34
KERN_INVALID_SECURITY       = 35
KERN_NOT_DEPRESSED          = 36
KERN_TERMINATED             = 37
KERN_LOCK_SET_DESTROYED     = 38
KERN_LOCK_UNSTABLE          = 39
KERN_LOCK_OWNED             = 40
KERN_LOCK_OWNED_SELF        = 41
KERN_SEMAPHORE_DESTROYED    = 42
KERN_RPC_SERVER_TERMINATED  = 43
KERN_RPC_TERMINATE_ORPHAN   = 44
KERN_RPC_CONTINUE_ORPHAN    = 45
KERN_NOT_SUPPORTED          = 46
KERN_NODE_DOWN              = 47
KERN_NOT_WAITING            = 48
KERN_OPERATION_TIMED_OUT    = 49
KERN_CODESIGN_ERROR         = 50
KERN_POLICY_STATIC          = 51
KERN_INSUFFICIENT_BUFFER_SIZE  = 52
KERN_RETURN_MAX             = 0x100

# CPU types 
CPU_ARCH_ABI64      =   0x01000000
CPU_TYPE_X86        =   7
CPU_TYPE_I386       =   CPU_TYPE_X86
CPU_TYPE_X86_64     =   CPU_ARCH_ABI64 | CPU_TYPE_X86

# mach mag flags
MACH_MSG_SUCCESS                =   0x00000000
MACH_MSG_MASK			        =   0x00003e00
MACH_MSG_IPC_SPACE		        =   0x00002000
MACH_MSG_VM_SPACE		        =   0x00001000
MACH_MSG_IPC_KERNEL		        =   0x00000800
MACH_MSG_VM_KERNEL		        =   0x00000400
MACH_SEND_IN_PROGRESS		    =   0x10000001
MACH_SEND_INVALID_DATA		    =   0x10000002
MACH_SEND_INVALID_DEST		    =   0x10000003
MACH_SEND_TIMED_OUT		        =   0x10000004
MACH_SEND_INVALID_VOUCHER	    =   0x10000005
MACH_SEND_INTERRUPTED		    =   0x10000007
MACH_SEND_MSG_TOO_SMALL		    =   0x10000008
MACH_SEND_INVALID_REPLY		    =   0x10000009
MACH_SEND_INVALID_RIGHT		    =   0x1000000a
MACH_SEND_INVALID_NOTIFY	    =   0x1000000b
MACH_SEND_INVALID_MEMORY	    =   0x1000000c
MACH_SEND_NO_BUFFER		        =   0x1000000d
MACH_SEND_TOO_LARGE		        =   0x1000000e
MACH_SEND_INVALID_TYPE		    =   0x1000000f
MACH_SEND_INVALID_HEADER	    =   0x10000010
MACH_SEND_INVALID_TRAILER	    =   0x10000011
MACH_SEND_INVALID_RT_OOL_SIZE	=   0x10000015
MACH_RCV_IN_PROGRESS		    =   0x10004001
MACH_RCV_INVALID_NAME		    =   0x10004002
MACH_RCV_TIMED_OUT		        =   0x10004003
MACH_RCV_TOO_LARGE		        =   0x10004004
MACH_RCV_INTERRUPTED		    =   0x10004005
MACH_RCV_PORT_CHANGED		    =   0x10004006
MACH_RCV_INVALID_NOTIFY		    =   0x10004007
MACH_RCV_INVALID_DATA		    =   0x10004008
MACH_RCV_PORT_DIED		        =   0x10004009
MACH_RCV_IN_SET			        =   0x1000400a
MACH_RCV_HEADER_ERROR		    =   0x1000400b
MACH_RCV_BODY_ERROR		        =   0x1000400c
MACH_RCV_INVALID_TYPE		    =   0x1000400d
MACH_RCV_SCATTER_SMALL		    =   0x1000400e
MACH_RCV_INVALID_TRAILER	    =   0x1000400f
MACH_RCV_IN_PROGRESS_TIMED      =   0x10004011

# CS opetions
CS_OPS_STATUS		        = 0
CS_OPS_MARKINVALID	        = 1
CS_OPS_MARKHARD		        = 2
CS_OPS_MARKKILL		        = 3
CS_OPS_CDHASH		        = 5
CS_OPS_PIDOFFSET	        = 6
CS_OPS_ENTITLEMENTS_BLOB    = 7
CS_OPS_MARKRESTRICT	        = 8
CS_OPS_SET_STATUS	        = 9
CS_OPS_BLOB		            = 10
CS_OPS_IDENTITY		        = 11
CS_OPS_CLEARINSTALLER	    = 12
CS_OPS_CLEARPLATFORM        = 13
CS_OPS_TEAMID               = 14
CS_MAX_TEAMID_LEN	        = 64

# code signing attributes of a proc
CS_VALID                    = 0x00000001
CS_ADHOC                    = 0x00000002
CS_GET_TASK_ALLOW           = 0x00000004
CS_INSTALLER                = 0x00000008
CS_FORCED_LV                = 0x00000010
CS_INVALID_ALLOWED          = 0x00000020
CS_HARD                     = 0x00000100
CS_KILL                     = 0x00000200
CS_CHECK_EXPIRATION         = 0x00000400
CS_RESTRICT                 = 0x00000800
CS_ENFORCEMENT              = 0x00001000
CS_REQUIRE_LV               = 0x00002000
CS_ENTITLEMENTS_VALIDATED   = 0x00004000
CS_NVRAM_UNRESTRICTED       = 0x00008000
CS_RUNTIME                  = 0x00010000
CS_ALLOWED_MACHO            = (CS_ADHOC | CS_HARD | CS_KILL | CS_CHECK_EXPIRATION | CS_RESTRICT | CS_ENFORCEMENT | CS_REQUIRE_LV | CS_RUNTIME)
CS_EXEC_SET_HARD            = 0x00100000
CS_EXEC_SET_KILL            = 0x00200000
CS_EXEC_SET_ENFORCEMENT     = 0x00400000
CS_EXEC_INHERIT_SIP         = 0x00800000
CS_KILLED                   = 0x01000000
CS_DYLD_PLATFORM            = 0x02000000
CS_PLATFORM_BINARY          = 0x04000000
CS_PLATFORM_PATH            = 0x08000000
CS_DEBUGGED                 = 0x10000000
CS_SIGNED                   = 0x20000000
CS_DEV_CODE                 = 0x40000000
CS_DATAVAULT_CONTROLLER     = 0x80000000
CS_ENTITLEMENT_FLAGS        = (CS_GET_TASK_ALLOW | CS_INSTALLER | CS_DATAVAULT_CONTROLLER | CS_NVRAM_UNRESTRICTED)

# executeable segment flags
CS_EXECSEG_MAIN_BINARY	    = 0x1
CS_EXECSEG_ALLOW_UNSIGNED   =0x10
CS_EXECSEG_DEBUGGER         = 0x20
CS_EXECSEG_JIT              = 0x40
CS_EXECSEG_SKIP_LV          = 0x80
CS_EXECSEG_CAN_LOAD_CDHASH  = 0x100
CS_EXECSEG_CAN_EXEC_CDHASH  = 0x200

# mach port options
MACH_MSG_OPTION_NONE        = 0x00000000
MACH_SEND_MSG               = 0x00000001
MACH_RCV_MSG                = 0x00000002
MACH_RCV_LARGE              = 0x00000004
MACH_RCV_LARGE_IDENTITY     = 0x00000008
MACH_SEND_TIMEOUT           = 0x00000010
MACH_SEND_OVERRIDE          = 0x00000020
MACH_SEND_INTERRUPT         = 0x00000040
MACH_SEND_NOTIFY            = 0x00000080
MACH_SEND_ALWAYS            = 0x00010000
MACH_SEND_TRAILER           = 0x00020000
MACH_SEND_NOIMPORTANCE      = 0x00040000
MACH_SEND_NODENAP           = MACH_SEND_NOIMPORTANCE
MACH_SEND_IMPORTANCE        = 0x00080000
MACH_SEND_SYNC_OVERRIDE     = 0x00100000
MACH_SEND_PROPAGATE_QOS     = 0x00200000
MACH_SEND_SYNC_USE_THRPRI	= MACH_SEND_PROPAGATE_QOS
MACH_SEND_KERNEL            = 0x00400000
MACH_RCV_TIMEOUT            = 0x00000100
MACH_RCV_NOTIFY             = 0x00000200
MACH_RCV_INTERRUPT          = 0x00000400
MACH_RCV_VOUCHER            = 0x00000800
MACH_RCV_OVERWRITE          = 0x00001000
MACH_RCV_SYNC_WAIT          = 0x00004000

MACH_RCV_TRAILER_NULL       = 0
MACH_RCV_TRAILER_SEQNO      = 1
MACH_RCV_TRAILER_SENDER     = 2
MACH_RCV_TRAILER_AUDIT      = 3
MACH_RCV_TRAILER_CTX        = 4
MACH_RCV_TRAILER_AV         = 7
MACH_RCV_TRAILER_LABELS     = 8
MACH_RCV_TRAILER_MASK       = (0xf << 24)
MACH_SEND_USER              = (MACH_SEND_MSG | MACH_SEND_TIMEOUT | \
                              MACH_SEND_NOTIFY | MACH_SEND_OVERRIDE | \
                              MACH_SEND_TRAILER | MACH_SEND_NOIMPORTANCE | \
                              MACH_SEND_SYNC_OVERRIDE | MACH_SEND_PROPAGATE_QOS)
MACH_RCV_USER               = (MACH_RCV_MSG | MACH_RCV_TIMEOUT | \
                              MACH_RCV_LARGE | MACH_RCV_LARGE_IDENTITY | \
                              MACH_RCV_VOUCHER | MACH_RCV_TRAILER_MASK | \
                              MACH_RCV_SYNC_WAIT)
MACH_MSG_OPTION_USER        = (MACH_SEND_USER | MACH_RCV_USER)


# inline int in error.d, not complate
EPERM           = 1
ENOENT          = 2
ESRCH           = 3
EINTR           = 4
EIO             = 5
ENXIO           = 6
E2BIG           = 7
ENOEXEC         = 8
EBADF           = 9
ECHILD          = 10
EDEADLK         = 11
ENOMEM          = 12
EACCES          = 13
EFAULT          = 14
ENOTBLK         = 15
EBUSY           = 16
EEXIST          = 17
EXDEV           = 18
ENODEV          = 19
ENOTDIR         = 20
EISDIR          = 21
EINVAL          = 22
ENFILE          = 23
EMFILE          = 24
ENOTTY          = 25
ETXTBSY         = 26
EFBIG           = 27
ENOSPC          = 28
ESPIPE          = 29
EROFS           = 30
EMLINK          = 31
EPIPE           = 32
EDOM            = 33
ERANGE          = 34
EAGAIN          = 35
EWOULDBLOCK     = 35
EINPROGRESS     = 36
EALREADY        = 37
ENOTSOCK        = 38
EDESTADDRREQ    = 39
EMSGSIZE        = 40
EPROTOTYPE      = 41
ENOPROTOOPT     = 42
EPROTONOSUPPORT = 43
ESOCKTNOSUPPORT = 44
ENOTSUP         = 45
EPFNOSUPPORT    = 46
EAFNOSUPPORT    = 47
EADDRINUSE      = 48
EADDRNOTAVAIL   = 49
ENETDOWN        = 50
ENETUNREACH     = 51
ENETRESET       = 52
ECONNABORTED    = 53
ECONNRESET      = 54
ENOBUFS         = 55
EISCONN         = 56
ENOTCONN        = 57
ESHUTDOWN       = 58
ETOOMANYREFS    = 59
ETIMEDOUT       = 60
ECONNREFUSED    = 61
ELOOP           = 62
ENAMETOOLONG    = 63
EHOSTDOWN       = 64
EHOSTUNREACH    = 65
ENOTEMPTY       = 66
EPROCLIM        = 67
EUSERS          = 68
EDQUOT          = 69
ESTALE          = 70
EREMOTE         = 71
EBADRPC         = 72
ERPCMISMATCH    = 73
EPROGUNAVAIL    = 74
EPROGMISMATCH   = 75
EPROCUNAVAIL    = 76
ENOLCK          = 77
ENOSYS          = 78
EFTYPE          = 79
EAUTH           = 80
ENEEDAUTH       = 81
EPWROFF         = 82
EDEVERR         = 83
EOVERFLOW       = 84
EBADEXEC        = 85
EBADARCH        = 86
ESHLIBVERS      = 87
EBADMACHO       = 88
ECANCELED       = 89
EIDRM           = 90
ENOMSG          = 91
EILSEQ          = 92
ENOATTR         = 93
EBADMSG         = 94
EMULTIHOP       = 95
ENODATA         = 96
ENOLINK         = 97
ENOSR           = 98
ENOSTR          = 99
EPROTO          = 100
ETIME           = 101
EOPNOTSUPP      = 102
ELAST           = 102


# shared region 
SHARED_REGION_BASE_I386	            = 0x90000000
SHARED_REGION_SIZE_I386             = 0x20000000
SHARED_REGION_NESTING_BASE_I386	    = 0x90000000
SHARED_REGION_NESTING_SIZE_I386	    = 0x20000000
SHARED_REGION_NESTING_MIN_I386      = 0x00200000
SHARED_REGION_NESTING_MAX_I386      = 0xFFE00000
SHARED_REGION_BASE_X86_64           = 0x00007FFF00000000
SHARED_REGION_SIZE_X86_64           = 0x00000000FFE00000
SHARED_REGION_NESTING_BASE_X86_64   = 0x00007FFF00000000
SHARED_REGION_NESTING_SIZE_X86_64   = 0x00000000FFE00000
SHARED_REGION_NESTING_MIN_X86_64    = 0x0000000000200000
SHARED_REGION_NESTING_MAX_X86_64    = 0xFFFFFFFFFFE00000
SHARED_REGION_BASE_PPC              = 0x90000000
SHARED_REGION_SIZE_PPC              = 0x20000000
SHARED_REGION_NESTING_BASE_PPC      = 0x90000000
SHARED_REGION_NESTING_SIZE_PPC      = 0x10000000
SHARED_REGION_NESTING_MIN_PPC       = 0x10000000
SHARED_REGION_NESTING_MAX_PPC       = 0x10000000
SHARED_REGION_BASE_PPC64            = 0x00007FFF60000000
SHARED_REGION_SIZE_PPC64            = 0x00000000A0000000
SHARED_REGION_NESTING_BASE_PPC64    = 0x00007FFF60000000
SHARED_REGION_NESTING_SIZE_PPC64    = 0x00000000A0000000
SHARED_REGION_NESTING_MIN_PPC64     = 0x0000000010000000
SHARED_REGION_NESTING_MAX_PPC64     = 0x0000000010000000
SHARED_REGION_BASE_ARM              = 0x1A000000
SHARED_REGION_SIZE_ARM              = 0x26000000
SHARED_REGION_NESTING_BASE_ARM      = 0x1A000000
SHARED_REGION_NESTING_SIZE_ARM      = 0x26000000


# fcntl 
F_DUPFD                             = 0
F_GETFD                             = 1
F_SETFD                             = 2
F_GETFL                             = 3
F_SETFL                             = 4
F_GETOWN                            = 5
F_SETOWN                            = 6
F_SETLK                             = 8
F_SETLKW                            = 9
F_SETLKWTIMEOUT                     = 10
F_DUPFD_CLOEXEC                     = 67
F_SETNOSIGPIPE                      = 73
F_GETNOSIGPIPE                      = 74
F_OFD_SETLK                         = 90
F_OFD_SETLKW                        = 91
F_OFD_SETLKWTIMEOUT                 = 93
F_SETCONFINED                       = 95
F_GETCONFINED                       = 96
F_ADDFILESIGS_RETURN                = 97

# proc info call numbers
PROC_INFO_CALL_LISTPIDS             = 0x1
PROC_INFO_CALL_PIDINFO              = 0x2
PROC_INFO_CALL_PIDFDINFO            = 0x3
PROC_INFO_CALL_KERNMSGBUF           = 0x4
PROC_INFO_CALL_SETCONTROL           = 0x5
PROC_INFO_CALL_PIDFILEPORTINFO      = 0x6
PROC_INFO_CALL_TERMINATE            = 0x7
PROC_INFO_CALL_DIRTYCONTROL         = 0x8
PROC_INFO_CALL_PIDRUSAGE            = 0x9
PROC_INFO_CALL_PIDORIGINATORINFO    = 0xa
PROC_INFO_CALL_LISTCOALITIONS       = 0xb
PROC_INFO_CALL_CANUSEFGHW           = 0xc
PROC_INFO_CALL_PIDDYNKQUEUEINFO     = 0xd
PROC_INFO_CALL_UDATA_INFO           = 0xe


PROC_PIDLISTFDS                     = 1
PROC_PIDTASKALLINFO2                = 2
PROC_PIDTBSDINFO                    = 3
PROC_PIDTASKINFO                    = 4
PROC_PIDTHREADINFO                  = 5
PROC_PIDLISTTHREADS                 = 6
PROC_PIDREGIONINFO                  = 7
PROC_PIDREGIONPATHINFO              = 8
PROC_PIDVNODEPATHINFO               = 9
PROC_PIDTHREADPATHINFO              = 10
PROC_PIDPATHINFO                    = 11
PROC_PIDWORKQUEUEINFO               = 12
PROC_PIDT_SHORTBSDINFO              = 13
PROC_PIDLISTFILEPORTS               = 14
PROC_PIDTHREADID64INFO              = 15
PROC_PID_RUSAGE                     = 16
PROC_PIDUNIQIDENTIFIERINFO          = 17
PROC_PIDT_BSDINFOWITHUNIQID         = 18
PROC_PIDARCHINFO                    = 19
PROC_PIDCOALITIONINFO               = 20
PROC_PIDNOTEEXIT                    = 21
PROC_PIDREGIONPATHINFO2             = 22
PROC_PIDREGIONPATHINFO3             = 23
PROC_PIDEXITREASONINFO              = 24
PROC_PIDEXITREASONBASICINFO         = 25
PROC_PIDLISTUPTRS                   = 26
PROC_PIDLISTDYNKQUEUES              = 27
PROC_PIDLISTTHREADIDS               = 28
PROC_PIDVMRTFAULTINFO               = 29

PROC_PIDREGIONPATHINFO_SIZE         = 1272

# syscall getattrlist
# common
ATTR_CMN_NAME                       = 0x00000001
ATTR_CMN_DEVID                      = 0x00000002
ATTR_CMN_FSID                       = 0x00000004
ATTR_CMN_OBJTYPE                    = 0x00000008
ATTR_CMN_OBJTAG                     = 0x00000010
ATTR_CMN_OBJID                      = 0x00000020
ATTR_CMN_OBJPERMANENTID             = 0x00000040
ATTR_CMN_PAROBJID                   = 0x00000080
ATTR_CMN_SCRIPT                     = 0x00000100
ATTR_CMN_CRTIME                     = 0x00000200
ATTR_CMN_MODTIME                    = 0x00000400
ATTR_CMN_CHGTIME                    = 0x00000800
ATTR_CMN_ACCTIME                    = 0x00001000
ATTR_CMN_BKUPTIME                   = 0x00002000
ATTR_CMN_FNDRINFO                   = 0x00004000
ATTR_CMN_OWNERID                    = 0x00008000
ATTR_CMN_GRPID                      = 0x00010000
ATTR_CMN_ACCESSMASK                 = 0x00020000
ATTR_CMN_FLAGS                      = 0x00040000
ATTR_CMN_GEN_COUNT                  = 0x00080000
ATTR_CMN_DOCUMENT_ID                = 0x00100000
ATTR_CMN_USERACCESS                 = 0x00200000
ATTR_CMN_EXTENDED_SECURITY          = 0x00400000
ATTR_CMN_UUID                       = 0x00800000
ATTR_CMN_GRPUUID                    = 0x01000000
ATTR_CMN_FILEID                     = 0x02000000
ATTR_CMN_PARENTID                   = 0x04000000
ATTR_CMN_FULLPATH                   = 0x08000000
ATTR_CMN_ADDEDTIME                  = 0x10000000
ATTR_CMN_ERROR                      = 0x20000000
ATTR_CMN_DATA_PROTECT_FLAGS         = 0x40000000
ATTR_CMN_RETURNED_ATTRS             = 0x80000000 
ATTR_CMN_VALIDMASK                  = 0xFFFFFFFF

# vnode type 
VNON                                = 0
VREG                                = 1
VDIR                                = 2
VBLK                                = 3
VCHR                                = 4
VLNK                                = 5
VSOCK                               = 6
VFIFO                               = 7
VBAD                                = 8
VSTR                                = 9
VCPLX                               = 10


# host info def values
HOST_BASIC_INFO                     = 1
HOST_SCHED_INFO                     = 3
HOST_RESOURCE_SIZES                 = 4
HOST_PRIORITY_INFO                  = 5
HOST_SEMAPHORE_TRAPS                = 7
HOST_MACH_MSG_TRAP                  = 8
HOST_VM_PURGABLE                    = 9
HOST_DEBUG_INFO_INTERNAL            = 10
HOST_CAN_HAS_DEBUGGER               = 11
HOST_PREFERRED_USER_ARCH            = 12


# commpage 
X8664_COMM_PAGE_START_ADDRESS       = 0x7FFFFFE00000
ARM64_COMM_PAGE_START_ADDRESS       = 0x0000000FFFFFC000

COMM_PAGE_SIGNATURE                 = 0x000   # first 16 bytes are a signature
COMM_PAGE_CPU_CAPABILITIES64        = 0x010   # uint64_t _cpu_capabilities
COMM_PAGE_UNUSED                    = 0x018   # 6 unused bytes
COMM_PAGE_VERSION                   = 0x01E   # 16-bit version
COMM_PAGE_THIS_VERSION              = 13      # in ver 13, _COMM_PAGE_NT_SHIFT defaults to 0 (was 32) 

COMM_PAGE_CPU_CAPABILITIES          = 0x020   # uint32_t _cpu_capabilities (retained for compatibility) */
COMM_PAGE_NCPUS                     = 0x022   # uint8_t number of configured CPUs (hw.logicalcpu at boot time) */
COMM_PAGE_UNUSED0                   = 0x024   # 2 unused bytes, previouly reserved for expansion of cpu_capabilities */
COMM_PAGE_CACHE_LINESIZE            = 0x026   # uint16_t cache line size */

COMM_PAGE_SCHED_GEN                 = 0x028	  # uint32_t scheduler generation number (count of pre-emptions) */
COMM_PAGE_MEMORY_PRESSURE           = 0x02c   # uint32_t copy of vm_memory_pressure */
COMM_PAGE_SPIN_COUNT                = 0x030	  # uint32_t max spin count for mutex's */

COMM_PAGE_ACTIVE_CPUS               = 0x034   # uint8_t number of active CPUs (hw.activecpu) */
COMM_PAGE_PHYSICAL_CPUS             = 0x035   # uint8_t number of physical CPUs (hw.physicalcpu_max) */
COMM_PAGE_LOGICAL_CPUS              = 0x036   # uint8_t number of logical CPUs (hw.logicalcpu_max) */
COMM_PAGE_UNUSED1                   = 0x037   # 1 unused bytes */
COMM_PAGE_MEMORY_SIZE               = 0x038   # uint64_t max memory size */

COMM_PAGE_CPUFAMILY                 = 0x040   # uint32_t hw.cpufamily, x86*/
COMM_PAGE_KDEBUG_ENABLE             = 0x044   # uint32_t export "kdebug_enable" to userspace */
COMM_PAGE_ATM_DIAGNOSTIC_CONFIG     = 0x48    # uint32_t export "atm_diagnostic_config" to userspace */

COMM_PAGE_UNUSED2                   = 0x04C   # [0x4C,0x50) unused */

COMM_PAGE_TIME_DATA_START           = 0x050   # base of offsets below (_NT_SCALE etc) */
COMM_PAGE_NT_TSC_BASE               = 0x050   # used by nanotime() */
COMM_PAGE_NT_SCALE                  = 0x058   # used by nanotime() */
COMM_PAGE_NT_SHIFT                  = 0x05c   # used by nanotime() */
COMM_PAGE_NT_NS_BASE                = 0x060   # used by nanotime() */
COMM_PAGE_NT_GENERATION             = 0x068   # used by nanotime() */
COMM_PAGE_GTOD_GENERATION           = 0x06c   # used by gettimeofday() */
COMM_PAGE_GTOD_NS_BASE              = 0x070   # used by gettimeofday() */
COMM_PAGE_GTOD_SEC_BASE             = 0x078   # used by gettimeofday() */

# APPROX_TIME must be aligned to 64-byte cache line size
COMM_PAGE_APPROX_TIME               = 0x080   # used by mach_approximate_time() */
COMM_PAGE_APPROX_TIME_SUPPORTED     = 0x088   # used by mach_approximate_time() */

# following entries to next cache line
COMM_PAGE_CONT_TIMEBASE             = 0x0C0   # used by mach_continuous_time() */
COMM_PAGE_BOOTTIME_USEC             = 0x0C8   # uint64_t boottime */

COMM_PAGE_END                       = 0xfff