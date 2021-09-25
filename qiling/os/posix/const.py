#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.const import *

# OS Threading Constants
THREAD_EVENT_INIT_VAL         = 0
THREAD_EVENT_EXIT_EVENT       = 1
THREAD_EVENT_UNEXECPT_EVENT   = 2
THREAD_EVENT_EXECVE_EVENT     = 3
THREAD_EVENT_CREATE_THREAD    = 4
THREAD_EVENT_BLOCKING_EVENT   = 5
THREAD_EVENT_EXIT_GROUP_EVENT = 6

# File Open Limits
NR_OPEN = 1024

SOCK_TYPE_MASK = 0x0f

linux_socket_types = {
    'SOCK_STREAM'    : 0x1,
    'SOCK_DGRAM'     : 0x2,
    'SOCK_RAW'       : 0x3,
    'SOCK_RDM'       : 0x4,
    'SOCK_SEQPACKET' : 0x5,
    'SOCK_DCCP'      : 0x6,
    'SOCK_PACKET'    : 0xa,
}


linux_socket_domain = {
    'AF_UNSPEC'    : 0x0,
    'AF_LOCAL'     : 0x1,
    'AF_INET'      : 0x2,
    'AF_AX25'      : 0x3,
    'AF_IPX'       : 0x4,
    'AF_APPLETALK' : 0x5,
    'AF_NETROM'    : 0x6,
    'AF_BRIDGE'    : 0x7,
    'AF_AAL5'      : 0x8,
    'AF_X25'       : 0x9,
    'AF_INET6'     : 0xa,
    'AF_MAX'       : 0xc,
}

# https://github.com/torvalds/linux/blob/master/include/uapi/linux/in.h
linux_socket_level = {
    'IPPROTO_IP'    : 0x0000,
    'SOL_SOCKET'    : 0x0001,
    'IPPROTO_TCP'   : 0x0006,
    'IPPROTO_UDP'   : 0x0011,
    'IPPROTO_IPV6'  : 0x0029,
    'IPPROTO_RAW'   : 0x00ff,
}


linux_socket_options = {
    "SO_DEBUG"           : 0x0001,
    "SO_REUSEADDR"       : 0x0002,
    "SO_KEEPALIVE"       : 0x0009,
    "SO_DONTROUTE"       : 0x0005,
    "SO_BROADCAST"       : 0x0006,
    "SO_LINGER"          : 0x000d,
    "SO_OOBINLINE"       : 0x000a,
    "SO_SNDBUF"          : 0x0007,
    "SO_RCVBUF"          : 0x0008,
    "SO_REUSEPORT"       : 0x000f,
    "SO_SNDLOWAT"        : 0x0013,
    "SO_RCVLOWAT"        : 0x0012,
    "SO_SNDTIMEO"        : 0x0015,
    "SO_RCVTIMEO"        : 0x0014,
}

# https://man7.org/linux/man-pages/man7/ip.7.html
# https://github.com/torvalds/linux/blob/master/include/uapi/linux/in.h
linux_socket_ip_options = {
    "IP_TOS"                    : 0x0001,
    "IP_TTL"                    : 0x0002,
    "IP_HDRINCL"                : 0x0003,
    "IP_OPTIONS"                : 0x0004,
    "IP_ROUTER_ALERT"           : 0x0005,
    "IP_RECVOPTS"               : 0x0006,
    "IP_RETOPTS"                : 0x0007,
    "IP_PKTINFO"                : 0x0008,
    "IP_MTU_DISCOVER"           : 0x000a,
    "IP_RECVERR"                : 0x000b,
    "IP_RECVTTL"                : 0x000c,
    "IP_RECVTOS"                : 0x000d,
    "IP_MTU"                    : 0x000e,
    "IP_FREEBIND"               : 0x000f,
    "IP_PASSSEC"                : 0x0012,
    "IP_TRANSPARENT"            : 0x0013,
    "IP_RECVORIGDSTADDR"        : 0x0014,
    "IP_NODEFRAG"               : 0x0016,
    "IP_BIND_ADDRESS_NO_PORT"   : 0x0018,
    "IP_MULTICAST_IF"           : 0x0020,
    "IP_MULTICAST_TTL"          : 0x0021,
    "IP_MULTICAST_LOOP"         : 0x0022,
    "IP_ADD_MEMBERSHIP"         : 0x0023,
    "IP_DROP_MEMBERSHIP"        : 0x0024,
    "IP_UNBLOCK_SOURCE"         : 0x0025,
    "IP_BLOCK_SOURCE"           : 0x0026,
    "IP_ADD_SOURCE_MEMBERSHIP"  : 0x0027,
    "IP_DROP_SOURCE_MEMBERSHIP" : 0x0028,
    "IP_MSFILTER"               : 0x0029,
    "IP_MULTICAST_ALL"          : 0x0031,
}


macos_socket_ip_options = {
    "IP_TOS"                   : 0x0003,
    "IP_TTL"                   : 0x0004,
    "IP_HDRINCL"               : 0x0002,
    "IP_OPTIONS"               : 0x0001,
    # "IP_ROUTER_ALERT"          : 0x0005,
    "IP_RECVOPTS"              : 0x0005,
    "IP_RETOPTS"               : 0x0008,
    # "IP_PKTINFO"               : 0x0008,
    # "IP_MTU_DISCOVER"          : 0x000a,
    # "IP_RECVERR"               : 0x000b,
    # "IP_RECVTTL"               : 0x000c,
    # "IP_RECVTOS"               : 0x000d,
    # "IP_MTU"                   : 0x000e,
    # "IP_FREEBIND"              : 0x000f,
    # "IP_PASSSEC"               : 0x0012,
    # "IP_TRANSPARENT"           : 0x0013,
    # "IP_RECVORIGDSTADDR"       : 0x0014,
    # "IP_NODEFRAG"              : 0x0016,
    # "IP_BIND_ADDRESS_NO_PORT"  : 0x0018,
    "IP_MULTICAST_IF"          : 0x0009,
    "IP_MULTICAST_TTL"         : 0x000a,
    "IP_MULTICAST_LOOP"        : 0x000b,
    "IP_ADD_MEMBERSHIP"        : 0x000c,
    "IP_DROP_MEMBERSHIP"       : 0x000d,
    # "IP_UNBLOCK_SOURCE"        : 0x0025,
    # "IP_BLOCK_SOURCE"          : 0x0026,
    # "IP_ADD_SOURCE_MEMBERSHIP" : 0x0027,
    # "IP_DROP_SOURCE_MEMBERSHIP" : 0x0028,
    # "IP_MSFILTER"              : 0x0029,
    # "IP_MULTICAST_ALL"         : 0x0031,
}


macos_socket_domain = {
    'AF_UNSPEC'    : 0x0,
    'AF_LOCAL'     : 0x1,
    'AF_INET'      : 0x2,
    'AF_IMPLINK'   : 0x3,
    'AF_PUP'       : 0x4,
    'AF_CHAOS'     : 0x5,
    'AF_NS'        : 0x6,
    'AF_ISO'       : 0x7,
    'AF_OSI'       : 0x7,
    'AF_ECMA'      : 0x8,
    'AF_DATAKIT'   : 0x9,
    'AF_CCITT'     : 0xa,
    'AF_SNA'       : 0xb,
    'AF_DECnet'    : 0xc,
    'AF_INET6'     : 0x1e,
}


# https://gfiber.googlesource.com/toolchains/mindspeed/+/refs/heads/newkernel_dev/arm-unknown-linux-gnueabi/sysroot/usr/include/bits/socket.h
arm_socket_types = {
    'SOCK_STREAM'    : 0x1,
    'SOCK_DGRAM'     : 0x2,
    'SOCK_RAW'       : 0x3,
    'SOCK_RDM'       : 0x4,
    'SOCK_SEQPACKET' : 0x5,
    'SOCK_DCCP'      : 0x6,
    'SOCK_PACKET'    : 0xa,
}


arm_socket_domain = {
    'AF_UNSPEC'     : 0x0,
    'AF_FILE'       : 0x1,
    'AF_UNIX'       : 0x1,
    'AF_LOCAL'      : 0x1,
    'AF_INET'       : 0x2,
    'AF_AX25'       : 0x3,
    'AF_IPX'        : 0x4,
    'AF_APPLETALK'  : 0x5,
    'AF_NETROM'     : 0x6,
    'AF_BRIDGE'     : 0x7,
    'AF_ATMPVC'     : 0x8,
    'AF_X25'        : 0x9,
    'AF_INET6'      : 0xa,
    'AF_ROSE'       : 0xb,
    'AF_DECnet'     : 0xc,
    'AF_NETBEUI'    : 0xd,
    'AF_SECURITY'   : 0xe,
    'AF_KEY'        : 0xf,
    'AF_NETLINK'    : 0x10,
    'AF_ROUTE'      : 0x10,
    'AF_PACKET'     : 0x11,
    'AF_ASH'        : 0x12,
    'AF_ECONET'     : 0x13,
    'AF_ATMSVC'     : 0x14,
    'AF_RDS'        : 0x15,
    'AF_SNA'        : 0x16,
    'AF_IRDA'       : 0x17,
    'AF_PPPOX'      : 0x18,
    'AF_WANPIPE'    : 0x19,
    'AF_LLC'        : 0x1a,
    'AF_IB'         : 0x1b,
    'AF_MPLS'       : 0x1c,
    'AF_CAN'        : 0x1d,
    'AF_TIPC'       : 0x1e,
    'AF_BLUETOOTH'  : 0x1f,
    'AF_IUCV'       : 0x20,
    'AF_RXRPC'      : 0x21,
    'AF_ISDN'       : 0x22,
    'AF_PHONE'      : 0x23,
    'AF_IEEE802154' : 0x24,
    'AF_CAIF'       : 0x25,
    'AF_ALG'        : 0x26,
    'AF_NFC'        : 0x27,
    'AF_VSOCK'      : 0x28,
    'AF_KCM'        : 0x29,
    'AF_QIPCRTR'    : 0x2a,
    'AF_SMC'        : 0x2b,
    'AF_MAX'        : 0x2c,
}


# https://gfiber.googlesource.com/toolchains/mindspeed/+/refs/heads/newkernel_dev/arm-unknown-linux-gnueabi/sysroot/usr/include/asm/socket.h
arm_socket_level = {
    'IPPROTO_IP'    : 0x0000,
    'SOL_SOCKET'    : 0x0001,
    'IPPROTO_TCP'   : 0x0006,
    'IPPROTO_UDP'   : 0x0011,
    'IPPROTO_IPV6'  : 0x0029,
    'IPPROTO_RAW'   : 0x00ff,
}

# https://gfiber.googlesource.com/toolchains/mindspeed/+/refs/heads/newkernel_dev/arm-unknown-linux-gnueabi/sysroot/usr/include/asm/socket.h
arm_socket_options = {
    "SO_DEBUG"           : 0x0001,
    "SO_REUSEADDR"       : 0x0002,
    "SO_KEEPALIVE"       : 0x0009,
    "SO_DONTROUTE"       : 0x0005,
    "SO_BROADCAST"       : 0x0006,
    "SO_LINGER"          : 0x000d,
    "SO_OOBINLINE"       : 0x000a,
    "SO_SNDBUF"          : 0x0007,
    "SO_RCVBUF"          : 0x0008,
    "SO_REUSEPORT"       : 0x000f,
    "SO_SNDLOWAT"        : 0x0013,
    "SO_RCVLOWAT"        : 0x0012,
    "SO_SNDTIMEO"        : 0x0015,
    "SO_RCVTIMEO"        : 0x0014,
}


mips_socket_types = {
    'SOCK_STREAM'    : 0x2,
    'SOCK_DGRAM'     : 0x1,
    'SOCK_RAW'       : 0x3,
    'SOCK_RDM'       : 0x4,
    'SOCK_SEQPACKET' : 0x5,
    'SOCK_DCCP'      : 0x6,
    'SOCK_PACKET'    : 0xa,
}


mips_socket_domain = {
    'AF_UNSPEC'     : 0x0,
    'AF_FILE'       : 0x1,
    'AF_UNIX'       : 0x1,
    'AF_LOCAL'      : 0x1,
    'AF_INET'       : 0x2,
    'AF_AX25'       : 0x3,
    'AF_IPX'        : 0x4,
    'AF_APPLETALK'  : 0x5,
    'AF_NETROM'     : 0x6,
    'AF_BRIDGE'     : 0x7,
    'AF_ATMPVC'     : 0x8,
    'AF_X25'        : 0x9,
    'AF_INET6'      : 0xa,
    'AF_ROSE'       : 0xb,
    'AF_DECnet'     : 0xc,
    'AF_NETBEUI'    : 0xd,
    'AF_SECURITY'   : 0xe,
    'AF_KEY'        : 0xf,
    'AF_NETLINK'    : 0x10,
    'AF_ROUTE'      : 0x10,
    'AF_PACKET'     : 0x11,
    'AF_ASH'        : 0x12,
    'AF_ECONET'     : 0x13,
    'AF_ATMSVC'     : 0x14,
    'AF_RDS'        : 0x15,
    'AF_SNA'        : 0x16,
    'AF_IRDA'       : 0x17,
    'AF_PPPOX'      : 0x18,
    'AF_WANPIPE'    : 0x19,
    'AF_LLC'        : 0x1a,
    'AF_IB'         : 0x1b,
    'AF_MPLS'       : 0x1c,
    'AF_CAN'        : 0x1d,
    'AF_TIPC'       : 0x1e,
    'AF_BLUETOOTH'  : 0x1f,
    'AF_IUCV'       : 0x20,
    'AF_RXRPC'      : 0x21,
    'AF_ISDN'       : 0x22,
    'AF_PHONE'      : 0x23,
    'AF_IEEE802154' : 0x24,
    'AF_CAIF'       : 0x25,
    'AF_ALG'        : 0x26,
    'AF_NFC'        : 0x27,
    'AF_VSOCK'      : 0x28,
    'AF_KCM'        : 0x29,
    'AF_QIPCRTR'    : 0x2a,
    'AF_SMC'        : 0x2b,
    'AF_MAX'        : 0x2c,
}

# https://docs.huihoo.com/doxygen/linux/kernel/3.7/arch_2mips_2include_2uapi_2asm_2socket_8h_source.html
# https://android-review.linaro.org/plugins/gitiles/platform/prebuilts/gcc/darwin-x86/mips/mipsel-linux-android-4.4.3/+/78060bd30f50c43c7442f32e7740efcdb87ba587/sysroot/usr/include/linux/in.h
mips_socket_level = {
    'SOL_SOCKET'    : 0xffff,
    'IPPROTO_IP'    : 0x0000,
    'IPPROTO_TCP'   : 0x0006,
    'IPPROTO_UDP'   : 0x0011,
    'IPPROTO_IPV6'  : 0x0029,
    'IPPROTO_RAW'   : 0x00ff,
}

# https://docs.huihoo.com/doxygen/linux/kernel/3.7/arch_2mips_2include_2uapi_2asm_2socket_8h_source.html
# https://github.com/torvalds/linux/blob/master/arch/mips/include/uapi/asm/socket.h
mips_socket_options = {
    "SO_DEBUG"                  : 0x0001,
    "SO_REUSEADDR"              : 0x0004,
    "SO_KEEPALIVE"              : 0x0008,
    "SO_DONTROUTE"              : 0x0010,
    "SO_BROADCAST"              : 0x0020,
    "SO_LINGER"                 : 0x0080,
    "SO_OOBINLINE"              : 0x0100,
    "SO_REUSEPORT"              : 0x0200,
    "SO_SNDBUF"                 : 0x1001,
    "SO_RCVBUF"                 : 0x1002,
    "SO_SNDLOWAT"               : 0x1003,
    "SO_RCVLOWAT"               : 0x1004,
    "SO_SNDTIMEO_OLD"           : 0x1005,
    "SO_RCVTIMEO_OLD"           : 0x1006,
    "SO_TIMESTAMP_OLD"          : 0x001d,
    # "SO_TIMESTAMPNS_OLD"        : 0x0023,
    # "SO_TIMESTAMPING_OLD"       : 0x0025,
    "SO_TIMESTAMP_NEW"          : 0x003f,
    "SO_TIMESTAMPNS_NEW"        : 0x0040,
    "SO_TIMESTAMPING_NEW"       : 0x0041,
    "SO_RCVTIMEO_NEW"           : 0x0042,
    "SO_SNDTIMEO_NEW"           : 0x0043,
}


mips_socket_ip_options = {
    "IP_TOS"                    : 0x0001,
    "IP_TTL"                    : 0x0002,
    "IP_HDRINCL"                : 0x0003,
    "IP_OPTIONS"                : 0x0004,
    "IP_ROUTER_ALERT"           : 0x0005,
    "IP_RECVOPTS"               : 0x0006,
    "IP_RETOPTS"                : 0x0007,
    "IP_PKTINFO"                : 0x0008,
    "IP_MTU_DISCOVER"           : 0x000a,
    "IP_RECVERR"                : 0x000b,
    "IP_RECVTTL"                : 0x000c,
    "IP_RECVTOS"                : 0x000d,
    "IP_MTU"                    : 0x000e,
    "IP_FREEBIND"               : 0x000f,
    "IP_PASSSEC"                : 0x0012,
    "IP_TRANSPARENT"            : 0x0013,
    "IP_RECVORIGDSTADDR"        : 0x0014,
    "IP_NODEFRAG"               : 0x0016,
    "IP_BIND_ADDRESS_NO_PORT"   : 0x0018,
    "IP_MULTICAST_IF"           : 0x0020,
    "IP_MULTICAST_TTL"          : 0x0021,
    "IP_MULTICAST_LOOP"         : 0x0022,
    "IP_ADD_MEMBERSHIP"         : 0x0023,
    "IP_DROP_MEMBERSHIP"        : 0x0024,
    "IP_UNBLOCK_SOURCE"         : 0x0025,
    "IP_BLOCK_SOURCE"           : 0x0026,
    "IP_ADD_SOURCE_MEMBERSHIP"  : 0x0027,
    "IP_DROP_SOURCE_MEMBERSHIP" : 0x0028,
    "IP_MSFILTER"               : 0x0029,
    "IP_MULTICAST_ALL"          : 0x0031,
    "SO_SNDTIMEO_OLD"           : 0x1005,
    "SO_RCVTIMEO_OLD"           : 0x1006,
    "SO_TIMESTAMP_OLD"          : 0x001d,
    # "SO_TIMESTAMPNS_OLD"        : 0x0023,
    # "SO_TIMESTAMPING_OLD"       : 0x0025,
    "SO_TIMESTAMP_NEW"          : 0x003f,
    "SO_TIMESTAMPNS_NEW"        : 0x0040,
    "SO_TIMESTAMPING_NEW"       : 0x0041,
    "SO_RCVTIMEO_NEW"           : 0x0042,
    "SO_SNDTIMEO_NEW"           : 0x0043,

}


mac_open_flags = {
    "O_RDONLY"   : 0x0000,
    "O_WRONLY"   : 0x0001,
    "O_RDWR"     : 0x0002,
    "O_NONBLOCK" : 0x0004,
    "O_APPEND"   : 0x0008,
    "O_ASYNC"    : 0x0040,
    "O_SYNC"     : 0x0080,
    "O_NOFOLLOW" : 0x0100,
    "O_CREAT"    : 0x0200,
    "O_TRUNC"    : 0x0400,
    "O_EXCL"     : 0x0800,
    "O_NOCTTY"   : 0x20000,
    "O_DIRECTORY": 0x100000
}


linux_open_flags = {
    'O_RDONLY'    : 0o000000000,
    'O_WRONLY'    : 0o000000001,
    'O_RDWR'      : 0o000000002,
    'O_CREAT'     : 0o000000100,
    'O_EXCL'      : 0o000000200,
    'O_NOCTTY'    : 0o000000400,
    'O_TRUNC'     : 0o000001000,
    'O_APPEND'    : 0o000002000,
    'O_NONBLOCK'  : 0o000004000,
    'O_DSYNC'     : 0o000010000,
    'FASYNC'      : 0o000020000,
    'O_DIRECT'    : 0o000040000,
    'O_LARGEFILE' : 0o000100000,
    'O_DIRECTORY' : 0o000200000,
    'O_NOFOLLOW'  : 0o000400000,
    'O_NOATIME'   : 0o001000000,
    'O_CLOEXEC'   : 0o002000000,
    'O_SYNC'      : 0o004000000 | 0o000010000, # O_DSYNC
    'O_PATH'      : 0o010000000
}


mips_open_flags = {
    'O_RDONLY'   : 0x0,
    'O_WRONLY'   : 0x1,
    'O_RDWR'     : 0x2,
    'O_APPEND'   : 0x8,
    'O_NONBLOCK' : 0x80,
    'O_CREAT'    : 0x100,
    'O_TRUNC'    : 0x200,
    'O_EXCL'     : 0x400,
    'O_NOCTTY'   : 0x800,
    'O_ASYNC'    : 0x1000,
    'O_SYNC'     : 0x4000,
    'O_NOFOLLOW' : 0x20000,
    'O_DIRECTORY': 0x100000,
}


arm_open_flags = {
    'O_RDONLY'   : 0x0,
    'O_WRONLY'   : 0x1,
    'O_RDWR'     : 0x2,
    'O_CREAT'    : 0x40,
    'O_EXCL'     : 0x80,
    'O_NOCTTY'   : 0x100,
    'O_TRUNC'    : 0x200,
    'O_APPEND'   : 0x400,
    'O_NONBLOCK' : 0x800,
    'O_ASYNC'    : 0x2000,
    'O_DIRECTORY': 0x10000,
    'O_NOFOLLOW' : 0x20000,
    'O_SYNC'     : 0x101000,
}

# fcntl flags
F_DUPFD		= 0
F_GETFD		= 1
F_SETFD		= 2
F_GETFL		= 3
F_SETFL		= 4
F_GETLK		= 5
F_SETLK		= 6
F_SETLKW	= 7

FD_CLOEXEC = 1

# error code
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
EAGAIN          = 11
EWOULDBLOCK     = 11
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
EDEADLK         = 35
ENAMETOOLONG    = 36
ENOLCK          = 37
ENOSYS          = 38
ENOTEMPTY       = 39
ELOOP           = 40
ENOMSG          = 42
EIDRM           = 43
ECHRNG          = 44
EL2NSYNC        = 45
EL3HLT          = 46
EL3RST          = 47
ELNRNG          = 48
EUNATCH         = 49
ENOCSI          = 50
EL2HLT          = 51
EBADE           = 52
EBADR           = 53
EXFULL          = 54
ENOANO          = 55
EBADRQC         = 56
EBADSLT         = 57
EBFONT          = 59
ENOSTR          = 60
ENODATA         = 61
ETIME           = 62
ENOSR           = 63
ENONET          = 64
ENOPKG          = 65
EREMOTE         = 66
ENOLINK         = 67
EADV            = 68
ESRMNT          = 69
ECOMM           = 70
EPROTO          = 71
EMULTIHOP       = 72
EDOTDOT         = 73
EBADMSG         = 74
EOVERFLOW       = 75
ENOTUNIQ        = 76
EBADFD          = 77
EREMCHG         = 78
ELIBACC         = 79
ELIBBAD         = 80
ELIBSCN         = 81
ELIBMAX         = 82
ELIBEXEC        = 83
EILSEQ          = 84
ERESTART        = 85
ESTRPIPE        = 86
EUSERS          = 87
ENOTSOCK        = 88
EDESTADDRREQ    = 89
EMSGSIZE        = 90
EPROTOTYPE      = 91
ENOPROTOOPT     = 92
EPROTONOSUPPORT = 93
ESOCKTNOSUPPORT = 94
EOPNOTSUPP      = 95
EPFNOSUPPORT    = 96
EAFNOSUPPORT    = 97
EADDRINUSE      = 98
EADDRNOTAVAIL   = 99
ENETDOWN        = 100
ENETUNREACH     = 101
ENETRESET       = 102
ECONNABORTED    = 103
ECONNRESET      = 104
ENOBUFS         = 105
EISCONN         = 106
ENOTCONN        = 107
ESHUTDOWN       = 108
ETOOMANYREFS    = 109
ETIMEDOUT       = 110
ECONNREFUSED    = 111
EHOSTDOWN       = 112
EHOSTUNREACH    = 113
EALREADY        = 114
EINPROGRESS     = 115
ESTALE          = 116
EUCLEAN         = 117
ENOTNAM         = 118
ENAVAIL         = 119
EISNAM          = 120
EREMOTEIO       = 121
EDQUOT          = 122
ENOMEDIUM       = 123
EMEDIUMTYPE     = 124
ECANCELED       = 125
ENOKEY          = 126
EKEYEXPIRED     = 127
EKEYREVOKED     = 128
EKEYREJECTED    = 129
EOWNERDEAD      = 130
ENOTRECOVERABLE = 131


errors = {
    1: 'EPERM',
    2: 'ENOENT',
    3: 'ESRCH',
    4: 'EINTR',
    5: 'EIO',
    6: 'ENXIO',
    7: 'E2BIG',
    8: 'ENOEXEC',
    9: 'EBADF',
    10: 'ECHILD',
    11: 'EAGAIN/EWOULDBLOCK',
    12: 'ENOMEM',
    13: 'EACCES',
    14: 'EFAULT',
    15: 'ENOTBLK',
    16: 'EBUSY',
    17: 'EEXIST',
    18: 'EXDEV',
    19: 'ENODEV',
    20: 'ENOTDIR',
    21: 'EISDIR',
    22: 'EINVAL',
    23: 'ENFILE',
    24: 'EMFILE',
    25: 'ENOTTY',
    26: 'ETXTBSY',
    27: 'EFBIG',
    28: 'ENOSPC',
    29: 'ESPIPE',
    30: 'EROFS',
    31: 'EMLINK',
    32: 'EPIPE',
    33: 'EDOM',
    34: 'ERANGE',
    35: 'EDEADLK',
    36: 'ENAMETOOLONG',
    37: 'ENOLCK',
    38: 'ENOSYS',
    39: 'ENOTEMPTY',
    40: 'ELOOP',
    42: 'ENOMSG',
    43: 'EIDRM',
    44: 'ECHRNG',
    45: 'EL2NSYNC',
    46: 'EL3HLT',
    47: 'EL3RST',
    48: 'ELNRNG',
    49: 'EUNATCH',
    50: 'ENOCSI',
    51: 'EL2HLT',
    52: 'EBADE',
    53: 'EBADR',
    54: 'EXFULL',
    55: 'ENOANO',
    56: 'EBADRQC',
    57: 'EBADSLT',
    59: 'EBFONT',
    60: 'ENOSTR',
    61: 'ENODATA',
    62: 'ETIME',
    63: 'ENOSR',
    64: 'ENONET',
    65: 'ENOPKG',
    66: 'EREMOTE',
    67: 'ENOLINK',
    68: 'EADV',
    69: 'ESRMNT',
    70: 'ECOMM',
    71: 'EPROTO',
    72: 'EMULTIHOP',
    73: 'EDOTDOT',
    74: 'EBADMSG',
    75: 'EOVERFLOW',
    76: 'ENOTUNIQ',
    77: 'EBADFD',
    78: 'EREMCHG',
    79: 'ELIBACC',
    80: 'ELIBBAD',
    81: 'ELIBSCN',
    82: 'ELIBMAX',
    83: 'ELIBEXEC',
    84: 'EILSEQ',
    85: 'ERESTART',
    86: 'ESTRPIPE',
    87: 'EUSERS',
    88: 'ENOTSOCK',
    89: 'EDESTADDRREQ',
    90: 'EMSGSIZE',
    91: 'EPROTOTYPE',
    92: 'ENOPROTOOPT',
    93: 'EPROTONOSUPPORT',
    94: 'ESOCKTNOSUPPORT',
    95: 'EOPNOTSUPP',
    96: 'EPFNOSUPPORT',
    97: 'EAFNOSUPPORT',
    98: 'EADDRINUSE',
    99: 'EADDRNOTAVAIL',
    100: 'ENETDOWN',
    101: 'ENETUNREACH',
    102: 'ENETRESET',
    103: 'ECONNABORTED',
    104: 'ECONNRESET',
    105: 'ENOBUFS',
    106: 'EISCONN',
    107: 'ENOTCONN',
    108: 'ESHUTDOWN',
    109: 'ETOOMANYREFS',
    110: 'ETIMEDOUT',
    111: 'ECONNREFUSED',
    112: 'EHOSTDOWN',
    113: 'EHOSTUNREACH',
    114: 'EALREADY',
    115: 'EINPROGRESS',
    116: 'ESTALE',
    117: 'EUCLEAN',
    118: 'ENOTNAM',
    119: 'ENAVAIL',
    120: 'EISNAM',
    121: 'EREMOTEIO',
    122: 'EDQUOT',
    123: 'ENOMEDIUM',
    124: 'EMEDIUMTYPE',
    125: 'ECANCELED',
    126: 'ENOKEY',
    127: 'EKEYEXPIRED',
    128: 'EKEYREVOKED',
    129: 'EKEYREJECTED',
    130: 'EOWNERDEAD',
    131: 'ENOTRECOVERABLE',
}

# shm syscall
IPC_CREAT = 8**3
IPC_EXCL = 2*(8**3)
IPC_NOWAIT = 4*(8**3)

SHM_RDONLY = 8**4
SHM_RND = 2*(8**4)
SHM_REMAP= 4*(8**4)
SHM_EXEC = 1*(8**5)