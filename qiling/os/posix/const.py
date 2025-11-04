#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from enum import Enum, Flag

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

# number of signals
NSIG = 32

SOCK_TYPE_MASK = 0x0f

class linux_x86_socket_types(Enum):
    SOCK_STREAM    = 0x00001
    SOCK_DGRAM     = 0x00002
    SOCK_RAW       = 0x00003
    SOCK_RDM       = 0x00004
    SOCK_SEQPACKET = 0x00005
    SOCK_DCCP      = 0x00006
    SOCK_PACKET    = 0x0000a
    SOCK_NONBLOCK  = 0x00800
    SOCK_CLOEXEC   = 0x80000


class linux_x86_socket_domain(Enum):
    AF_UNSPEC    = 0x0
    AF_LOCAL     = 0x1
    AF_INET      = 0x2
    AF_AX25      = 0x3
    AF_IPX       = 0x4
    AF_APPLETALK = 0x5
    AF_NETROM    = 0x6
    AF_BRIDGE    = 0x7
    AF_AAL5      = 0x8
    AF_X25       = 0x9
    AF_INET6     = 0xa
    AF_MAX       = 0xc


# https://github.com/torvalds/linux/blob/master/include/uapi/linux/in.h
class linux_x86_socket_level(Enum):
    IPPROTO_IP   = 0x0000
    SOL_SOCKET   = 0x0001
    IPPROTO_TCP  = 0x0006
    IPPROTO_UDP  = 0x0011
    IPPROTO_IPV6 = 0x0029
    IPPROTO_RAW  = 0x00ff


# https://github.com/torvalds/linux/blob/master/tools/include/uapi/asm-generic/socket.h
class linux_x86_socket_options(Enum):
    SO_DEBUG        = 0x0001
    SO_REUSEADDR    = 0x0002
    SO_TYPE         = 0x0003
    SO_ERROR        = 0x0004
    SO_DONTROUTE    = 0x0005
    SO_BROADCAST    = 0x0006
    SO_SNDBUF       = 0x0007
    SO_RCVBUF       = 0x0008
    SO_SNDBUFFORCE  = 0x0020
    SO_RCVBUFFORCE  = 0x0021
    SO_KEEPALIVE    = 0x0009
    SO_OOBINLINE    = 0x000a
    SO_NO_CHECK     = 0x000b
    SO_PRIORITY     = 0x000c
    SO_LINGER       = 0x000d
    SO_BSDCOMPAT    = 0x000e
    SO_REUSEPORT    = 0x000f
    SO_PASSCRED     = 0x0010
    SO_PEERCRED     = 0x0011
    SO_RCVLOWAT     = 0x0012
    SO_SNDLOWAT     = 0x0013
    SO_RCVTIMEO_OLD = 0x0014
    SO_SNDTIMEO_OLD = 0x0015


# https://man7.org/linux/man-pages/man7/ip.7.html
# https://github.com/torvalds/linux/blob/master/include/uapi/linux/in.h
class linux_socket_ip_options(Enum):
    IP_TOS                    = 0x0001
    IP_TTL                    = 0x0002
    IP_HDRINCL                = 0x0003
    IP_OPTIONS                = 0x0004
    IP_ROUTER_ALERT           = 0x0005
    IP_RECVOPTS               = 0x0006
    IP_RETOPTS                = 0x0007
    IP_PKTINFO                = 0x0008
    IP_MTU_DISCOVER           = 0x000a
    IP_RECVERR                = 0x000b
    IP_RECVTTL                = 0x000c
    IP_RECVTOS                = 0x000d
    IP_MTU                    = 0x000e
    IP_FREEBIND               = 0x000f
    IP_PASSSEC                = 0x0012
    IP_TRANSPARENT            = 0x0013
    IP_RECVORIGDSTADDR        = 0x0014
    IP_NODEFRAG               = 0x0016
    IP_BIND_ADDRESS_NO_PORT   = 0x0018
    IP_MULTICAST_IF           = 0x0020
    IP_MULTICAST_TTL          = 0x0021
    IP_MULTICAST_LOOP         = 0x0022
    IP_ADD_MEMBERSHIP         = 0x0023
    IP_DROP_MEMBERSHIP        = 0x0024
    IP_UNBLOCK_SOURCE         = 0x0025
    IP_BLOCK_SOURCE           = 0x0026
    IP_ADD_SOURCE_MEMBERSHIP  = 0x0027
    IP_DROP_SOURCE_MEMBERSHIP = 0x0028
    IP_MSFILTER               = 0x0029
    IP_MULTICAST_ALL          = 0x0031


# https://github.com/torvalds/linux/blob/master/include/uapi/linux/tcp.h
class linux_socket_tcp_options(Enum):
    TCP_NODELAY              = 0x01
    TCP_MAXSEG               = 0x02
    TCP_CORK                 = 0x03
    TCP_KEEPIDLE             = 0x04
    TCP_KEEPINTVL            = 0x05
    TCP_KEEPCNT              = 0x06
    TCP_SYNCNT               = 0x07
    TCP_LINGER2              = 0x08
    TCP_DEFER_ACCEPT         = 0x09
    TCP_WINDOW_CLAMP         = 0x0a
    TCP_INFO                 = 0x0b
    TCP_QUICKACK             = 0x0c
    TCP_CONGESTION           = 0x0d
    TCP_MD5SIG               = 0x0e
    TCP_THIN_LINEAR_TIMEOUTS = 0x10
    TCP_THIN_DUPACK          = 0x11
    TCP_USER_TIMEOUT         = 0x12
    TCP_REPAIR               = 0x13
    TCP_REPAIR_QUEUE         = 0x14
    TCP_QUEUE_SEQ            = 0x15
    TCP_REPAIR_OPTIONS       = 0x16
    TCP_FASTOPEN             = 0x17
    TCP_TIMESTAMP            = 0x18
    TCP_NOTSENT_LOWAT        = 0x19
    TCP_CC_INFO              = 0x1a
    TCP_SAVE_SYN             = 0x1b
    TCP_SAVED_SYN            = 0x1c
    TCP_REPAIR_WINDOW        = 0x1d
    TCP_FASTOPEN_CONNECT     = 0x1e
    TCP_ULP                  = 0x1f
    TCP_MD5SIG_EXT           = 0x20
    TCP_FASTOPEN_KEY         = 0x21
    TCP_FASTOPEN_NO_COOKIE   = 0x22
    TCP_ZEROCOPY_RECEIVE     = 0x23
    TCP_INQ                  = 0x24
    TCP_TX_DELAY             = 0x25


class macos_socket_ip_options(Enum):
    IP_TOS                   = 0x03
    IP_TTL                   = 0x04
    IP_HDRINCL               = 0x02
    IP_OPTIONS               = 0x01
    # IP_ROUTER_ALERT        = 0x05
    IP_RECVOPTS              = 0x05
    IP_RETOPTS               = 0x08
    # IP_PKTINFO             = 0x08
    # IP_MTU_DISCOVER        = 0x0a
    # IP_RECVERR             = 0x0b
    # IP_RECVTTL             = 0x0c
    # IP_RECVTOS             = 0x0d
    # IP_MTU                 = 0x0e
    # IP_FREEBIND            = 0x0f
    # IP_PASSSEC             = 0x12
    # IP_TRANSPARENT         = 0x13
    # IP_RECVORIGDSTADDR     = 0x14
    # IP_NODEFRAG            = 0x16
    # IP_BIND_ADDRESS_NO_PORT= 0x18
    IP_MULTICAST_IF          = 0x09
    IP_MULTICAST_TTL         = 0x0a
    IP_MULTICAST_LOOP        = 0x0b
    IP_ADD_MEMBERSHIP        = 0x0c
    IP_DROP_MEMBERSHIP       = 0x0d
    # IP_UNBLOCK_SOURCE      = 0x25
    # IP_BLOCK_SOURCE        = 0x26
    # IP_ADD_SOURCE_MEMBERSHIP  = 0x27
    # IP_DROP_SOURCE_MEMBERSHIP = 0x28
    # IP_MSFILTER            = 0x29
    # IP_MULTICAST_ALL       = 0x31


class macos_x86_socket_domain(Enum):
    AF_UNSPEC  = 0x00
    AF_LOCAL   = 0x01
    AF_INET    = 0x02
    AF_IMPLINK = 0x03
    AF_PUP     = 0x04
    AF_CHAOS   = 0x05
    AF_NS      = 0x06
    AF_ISO     = 0x07
    AF_OSI     = 0x07
    AF_ECMA    = 0x08
    AF_DATAKIT = 0x09
    AF_CCITT   = 0x0a
    AF_SNA     = 0x0b
    AF_DECnet  = 0x0c
    AF_INET6   = 0x1e


# https://gfiber.googlesource.com/toolchains/mindspeed/+/refs/heads/newkernel_dev/arm-unknown-linux-gnueabi/sysroot/usr/include/bits/socket.h
class linux_arm_socket_types(Enum):
    SOCK_STREAM    = 0x00001
    SOCK_DGRAM     = 0x00002
    SOCK_RAW       = 0x00003
    SOCK_RDM       = 0x00004
    SOCK_SEQPACKET = 0x00005
    SOCK_DCCP      = 0x00006
    SOCK_PACKET    = 0x0000a
    SOCK_NONBLOCK  = 0x00800
    SOCK_CLOEXEC   = 0x80000


class linux_arm_socket_domain(Enum):
    AF_UNSPEC     = 0x00
    AF_FILE       = 0x01
    AF_UNIX       = 0x01
    AF_LOCAL      = 0x01
    AF_INET       = 0x02
    AF_AX25       = 0x03
    AF_IPX        = 0x04
    AF_APPLETALK  = 0x05
    AF_NETROM     = 0x06
    AF_BRIDGE     = 0x07
    AF_ATMPVC     = 0x08
    AF_X25        = 0x09
    AF_INET6      = 0x0a
    AF_ROSE       = 0x0b
    AF_DECnet     = 0x0c
    AF_NETBEUI    = 0x0d
    AF_SECURITY   = 0x0e
    AF_KEY        = 0x0f
    AF_NETLINK    = 0x10
    AF_ROUTE      = 0x10
    AF_PACKET     = 0x11
    AF_ASH        = 0x12
    AF_ECONET     = 0x13
    AF_ATMSVC     = 0x14
    AF_RDS        = 0x15
    AF_SNA        = 0x16
    AF_IRDA       = 0x17
    AF_PPPOX      = 0x18
    AF_WANPIPE    = 0x19
    AF_LLC        = 0x1a
    AF_IB         = 0x1b
    AF_MPLS       = 0x1c
    AF_CAN        = 0x1d
    AF_TIPC       = 0x1e
    AF_BLUETOOTH  = 0x1f
    AF_IUCV       = 0x20
    AF_RXRPC      = 0x21
    AF_ISDN       = 0x22
    AF_PHONE      = 0x23
    AF_IEEE802154 = 0x24
    AF_CAIF       = 0x25
    AF_ALG        = 0x26
    AF_NFC        = 0x27
    AF_VSOCK      = 0x28
    AF_KCM        = 0x29
    AF_QIPCRTR    = 0x2a
    AF_SMC        = 0x2b
    AF_MAX        = 0x2c


# https://gfiber.googlesource.com/toolchains/mindspeed/+/refs/heads/newkernel_dev/arm-unknown-linux-gnueabi/sysroot/usr/include/asm/socket.h
class linux_arm_socket_level(Enum):
    IPPROTO_IP   = 0x00
    SOL_SOCKET   = 0x01
    IPPROTO_TCP  = 0x06
    IPPROTO_UDP  = 0x11
    IPPROTO_IPV6 = 0x29
    IPPROTO_RAW  = 0xff


# https://gfiber.googlesource.com/toolchains/mindspeed/+/refs/heads/newkernel_dev/arm-unknown-linux-gnueabi/sysroot/usr/include/asm/socket.h
class linux_arm_socket_options(Enum):
    SO_DEBUG     = 0x01
    SO_REUSEADDR = 0x02
    SO_TYPE      = 0x03
    SO_ERROR     = 0x04
    SO_DONTROUTE = 0x05
    SO_BROADCAST = 0x06
    SO_SNDBUF    = 0x07
    SO_RCVBUF    = 0x08
    SO_KEEPALIVE = 0x09
    SO_OOBINLINE = 0x0a
    SO_LINGER    = 0x0d
    SO_REUSEPORT = 0x0f
    SO_SNDLOWAT  = 0x13
    SO_RCVLOWAT  = 0x12
    SO_SNDTIMEO  = 0x15
    SO_RCVTIMEO  = 0x14


class linux_mips_socket_types(Enum):
    SOCK_STREAM    = 0x2
    SOCK_DGRAM     = 0x1
    SOCK_RAW       = 0x3
    SOCK_RDM       = 0x4
    SOCK_SEQPACKET = 0x5
    SOCK_DCCP      = 0x6
    SOCK_PACKET    = 0xa


class linux_mips_socket_domain(Enum):
    AF_UNSPEC     = 0x00
    AF_FILE       = 0x01
    AF_UNIX       = 0x01
    AF_LOCAL      = 0x01
    AF_INET       = 0x02
    AF_AX25       = 0x03
    AF_IPX        = 0x04
    AF_APPLETALK  = 0x05
    AF_NETROM     = 0x06
    AF_BRIDGE     = 0x07
    AF_ATMPVC     = 0x08
    AF_X25        = 0x09
    AF_INET6      = 0x0a
    AF_ROSE       = 0x0b
    AF_DECnet     = 0x0c
    AF_NETBEUI    = 0x0d
    AF_SECURITY   = 0x0e
    AF_KEY        = 0x0f
    AF_NETLINK    = 0x10
    AF_ROUTE      = 0x10
    AF_PACKET     = 0x11
    AF_ASH        = 0x12
    AF_ECONET     = 0x13
    AF_ATMSVC     = 0x14
    AF_RDS        = 0x15
    AF_SNA        = 0x16
    AF_IRDA       = 0x17
    AF_PPPOX      = 0x18
    AF_WANPIPE    = 0x19
    AF_LLC        = 0x1a
    AF_IB         = 0x1b
    AF_MPLS       = 0x1c
    AF_CAN        = 0x1d
    AF_TIPC       = 0x1e
    AF_BLUETOOTH  = 0x1f
    AF_IUCV       = 0x20
    AF_RXRPC      = 0x21
    AF_ISDN       = 0x22
    AF_PHONE      = 0x23
    AF_IEEE802154 = 0x24
    AF_CAIF       = 0x25
    AF_ALG        = 0x26
    AF_NFC        = 0x27
    AF_VSOCK      = 0x28
    AF_KCM        = 0x29
    AF_QIPCRTR    = 0x2a
    AF_SMC        = 0x2b
    AF_MAX        = 0x2c

# https://docs.huihoo.com/doxygen/linux/kernel/3.7/arch_2mips_2include_2uapi_2asm_2socket_8h_source.html
# https://android-review.linaro.org/plugins/gitiles/platform/prebuilts/gcc/darwin-x86/mips/mipsel-linux-android-4.4.3/+/78060bd30f50c43c7442f32e7740efcdb87ba587/sysroot/usr/include/linux/in.h
class linux_mips_socket_level(Enum):
    SOL_SOCKET   = 0xffff
    IPPROTO_IP   = 0x0000
    IPPROTO_TCP  = 0x0006
    IPPROTO_UDP  = 0x0011
    IPPROTO_IPV6 = 0x0029
    IPPROTO_RAW  = 0x00ff


# https://docs.huihoo.com/doxygen/linux/kernel/3.7/arch_2mips_2include_2uapi_2asm_2socket_8h_source.html
# https://github.com/torvalds/linux/blob/master/arch/mips/include/uapi/asm/socket.h
class linux_mips_socket_options(Enum):
    SO_DEBUG              = 0x01
    SO_REUSEADDR          = 0x04
    SO_KEEPALIVE          = 0x08
    SO_DONTROUTE          = 0x10
    SO_BINDTODEVICE       = 0x19
    SO_BROADCAST          = 0x20
    SO_LINGER             = 0x80
    SO_OOBINLINE          = 0x00
    SO_REUSEPORT          = 0x00
    SO_SNDBUF             = 0x01
    SO_RCVBUF             = 0x02
    SO_SNDLOWAT           = 0x03
    SO_RCVLOWAT           = 0x04
    SO_SNDTIMEO_OLD       = 0x05
    SO_RCVTIMEO_OLD       = 0x06
    SO_TIMESTAMP_OLD      = 0x1d
    # SO_TIMESTAMPNS_OLD  = 0x23
    # SO_TIMESTAMPING_OLD = 0x25
    SO_TIMESTAMP_NEW      = 0x3f
    SO_TIMESTAMPNS_NEW    = 0x40
    SO_TIMESTAMPING_NEW   = 0x41
    SO_RCVTIMEO_NEW       = 0x42
    SO_SNDTIMEO_NEW       = 0x43


class linux_mips_socket_ip_options(Enum):
    IP_TOS                    = 0x0001
    IP_TTL                    = 0x0002
    IP_HDRINCL                = 0x0003
    IP_OPTIONS                = 0x0004
    IP_ROUTER_ALERT           = 0x0005
    IP_RECVOPTS               = 0x0006
    IP_RETOPTS                = 0x0007
    IP_PKTINFO                = 0x0008
    IP_MTU_DISCOVER           = 0x000a
    IP_RECVERR                = 0x000b
    IP_RECVTTL                = 0x000c
    IP_RECVTOS                = 0x000d
    IP_MTU                    = 0x000e
    IP_FREEBIND               = 0x000f
    IP_PASSSEC                = 0x0012
    IP_TRANSPARENT            = 0x0013
    IP_RECVORIGDSTADDR        = 0x0014
    IP_NODEFRAG               = 0x0016
    IP_BIND_ADDRESS_NO_PORT   = 0x0018
    IP_MULTICAST_IF           = 0x0020
    IP_MULTICAST_TTL          = 0x0021
    IP_MULTICAST_LOOP         = 0x0022
    IP_ADD_MEMBERSHIP         = 0x0023
    IP_DROP_MEMBERSHIP        = 0x0024
    IP_UNBLOCK_SOURCE         = 0x0025
    IP_BLOCK_SOURCE           = 0x0026
    IP_ADD_SOURCE_MEMBERSHIP  = 0x0027
    IP_DROP_SOURCE_MEMBERSHIP = 0x0028
    IP_MSFILTER               = 0x0029
    IP_MULTICAST_ALL          = 0x0031
    SO_SNDTIMEO_OLD           = 0x1005
    SO_RCVTIMEO_OLD           = 0x1006
    SO_TIMESTAMP_OLD          = 0x001d
    # SO_TIMESTAMPNS_OLD      = 0x0023
    # SO_TIMESTAMPING_OLD     = 0x0025
    SO_TIMESTAMP_NEW          = 0x003f
    SO_TIMESTAMPNS_NEW        = 0x0040
    SO_TIMESTAMPING_NEW       = 0x0041
    SO_RCVTIMEO_NEW           = 0x0042
    SO_SNDTIMEO_NEW           = 0x0043



class QlPrettyFlag(Flag):
    """Subclass the Flag type to provide a more adequate string representation.
    """

    def __str__(self) -> str:
        _, _, s = super().__str__().partition('.')

        return s.replace('|', ' | ')

################################
#          open flags          #
################################

FLAG_UNSUPPORTED = -1

class macos_x86_open_flags(QlPrettyFlag):
    O_RDONLY    = 0x000000
    O_WRONLY    = 0x000001
    O_RDWR      = 0x000002
    O_NONBLOCK  = 0x000004
    O_APPEND    = 0x000008
    O_ASYNC     = 0x000040
    O_SYNC      = 0x000080
    O_NOFOLLOW  = 0x000100
    O_CREAT     = 0x000200
    O_TRUNC     = 0x000400
    O_EXCL      = 0x000800
    O_NOCTTY    = 0x020000
    O_DIRECTORY = 0x100000
    O_BINARY    = FLAG_UNSUPPORTED
    O_LARGEFILE = FLAG_UNSUPPORTED


class linux_x86_open_flags(QlPrettyFlag):
    O_RDONLY    = 0x000000
    O_WRONLY    = 0x000001
    O_RDWR      = 0x000002
    O_NONBLOCK  = 0x000800
    O_APPEND    = 0x000400
    O_ASYNC     = 0x002000
    O_SYNC      = 0x101000
    O_NOFOLLOW  = 0x020000
    O_CREAT     = 0x000040
    O_TRUNC     = 0x000200
    O_EXCL      = 0x000080
    O_NOCTTY    = 0x000100
    O_DIRECTORY = 0x010000
    O_BINARY    = FLAG_UNSUPPORTED
    O_LARGEFILE = FLAG_UNSUPPORTED


class linux_arm_open_flags(QlPrettyFlag):
    O_RDONLY    = 0x000000
    O_WRONLY    = 0x000001
    O_RDWR      = 0x000002
    O_NONBLOCK  = 0x000800
    O_APPEND    = 0x000400
    O_ASYNC     = 0x002000
    O_SYNC      = 0x101000
    O_NOFOLLOW  = 0x008000
    O_CREAT     = 0x000040
    O_TRUNC     = 0x000200
    O_EXCL      = 0x000080
    O_NOCTTY    = 0x000100
    O_DIRECTORY = 0x004000
    O_BINARY    = FLAG_UNSUPPORTED
    O_LARGEFILE = 0x020000


class linux_mips_open_flags(QlPrettyFlag):
    O_RDONLY    = 0x000000
    O_WRONLY    = 0x000001
    O_RDWR      = 0x000002
    O_NONBLOCK  = 0x000080
    O_APPEND    = 0x000008
    O_ASYNC     = 0x001000
    O_SYNC      = 0x004010
    O_NOFOLLOW  = 0x020000
    O_CREAT     = 0x000100
    O_TRUNC     = 0x000200
    O_EXCL      = 0x000400
    O_NOCTTY    = 0x000800
    O_DIRECTORY = 0x010000
    O_BINARY    = FLAG_UNSUPPORTED
    O_LARGEFILE = 0x002000


class linux_riscv_open_flags(QlPrettyFlag):
    O_RDONLY    = 0x000000
    O_WRONLY    = 0x000001
    O_RDWR      = 0x000002
    O_NONBLOCK  = 0x000800
    O_APPEND    = 0x000400
    O_ASYNC     = 0x002000
    O_SYNC      = 0x101000
    O_NOFOLLOW  = 0x020000
    O_CREAT     = 0x000040
    O_TRUNC     = 0x000200
    O_EXCL      = 0x000080
    O_NOCTTY    = 0x000100
    O_DIRECTORY = 0x010000
    O_BINARY    = FLAG_UNSUPPORTED
    O_LARGEFILE = FLAG_UNSUPPORTED


class linux_ppc_open_flags(QlPrettyFlag):
    O_RDONLY    = 0x000000
    O_WRONLY    = 0x000001
    O_RDWR      = 0x000002
    O_NONBLOCK  = 0x000800
    O_APPEND    = 0x000400
    O_ASYNC     = 0x002000
    O_SYNC      = 0x101000
    O_NOFOLLOW  = 0x008000
    O_CREAT     = 0x000040
    O_TRUNC     = 0x000200
    O_EXCL      = 0x000080
    O_NOCTTY    = 0x000100
    O_DIRECTORY = 0x004000
    O_BINARY    = FLAG_UNSUPPORTED
    O_LARGEFILE = 0x010000


class freebsd_x86_open_flags(QlPrettyFlag):
    O_RDONLY    = 0x000000
    O_WRONLY    = 0x000001
    O_RDWR      = 0x000002
    O_NONBLOCK  = 0x000004
    O_APPEND    = 0x000008
    O_ASYNC     = 0x000040
    O_SYNC      = 0x000080
    O_NOFOLLOW  = 0x000100
    O_CREAT     = 0x000200
    O_TRUNC     = 0x000400
    O_EXCL      = 0x000800
    O_NOCTTY    = 0x008000
    O_DIRECTORY = 0x20000
    O_BINARY    = FLAG_UNSUPPORTED
    O_LARGEFILE = FLAG_UNSUPPORTED


class windows_x86_open_flags(QlPrettyFlag):
    O_RDONLY    = 0x000000
    O_WRONLY    = 0x000001
    O_RDWR      = 0x000002
    O_NONBLOCK  = FLAG_UNSUPPORTED
    O_APPEND    = 0x000008
    O_ASYNC     = FLAG_UNSUPPORTED
    O_SYNC      = FLAG_UNSUPPORTED
    O_NOFOLLOW  = FLAG_UNSUPPORTED
    O_CREAT     = 0x000100
    O_TRUNC     = 0x000200
    O_EXCL      = 0x000400
    O_NOCTTY    = FLAG_UNSUPPORTED
    O_DIRECTORY = FLAG_UNSUPPORTED
    O_BINARY    = 0x008000
    O_LARGEFILE = FLAG_UNSUPPORTED


class qnx_arm_open_flags(QlPrettyFlag):
    O_RDONLY    = 0x00000
    O_WRONLY    = 0x00001
    O_RDWR      = 0x00002
    O_NONBLOCK  = 0x00080
    O_APPEND    = 0x00008
    O_ASYNC     = 0x10000
    O_SYNC      = 0x00020
    O_NOFOLLOW  = FLAG_UNSUPPORTED
    O_CREAT     = 0x00100
    O_TRUNC     = 0x00200
    O_EXCL      = 0x00400
    O_NOCTTY    = 0x00800
    O_DIRECTORY = FLAG_UNSUPPORTED
    O_BINARY    = FLAG_UNSUPPORTED
    O_LARGEFILE = 0x08000


################################
#          mmap flags          #
################################

# see: https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/mman-common.h
class linux_mmap_flags(Flag):
    MAP_FILE            = 0x00000000
    MAP_SHARED          = 0x00000001
    MAP_PRIVATE         = 0x00000002

    MAP_FIXED           = 0x00000010
    MAP_ANONYMOUS       = 0x00000020
    MAP_GROWSDOWN       = 0x00000100
    MAP_DENYWRITE       = 0x00000800
    MAP_EXECUTABLE      = 0x00001000
    MAP_LOCKED          = 0x00002000
    MAP_NORESERVE       = 0x00004000
    MAP_POPULATE        = 0x00008000
    MAP_NONBLOCK        = 0x00010000
    MAP_STACK           = 0x00020000
    MAP_HUGETLB         = 0x00040000
    MAP_SYNC            = 0x00080000
    MAP_FIXED_NOREPLACE = 0x00100000
    MAP_UNINITIALIZED   = 0x04000000


# see: https://github.com/freebsd/freebsd-src/blob/master/sys/sys/mman.h
class freebsd_mmap_flags(Flag):
    MAP_FILE            = 0x00000000
    MAP_SHARED          = 0x00000001
    MAP_PRIVATE         = 0x00000002

    MAP_FIXED           = 0x00000010
    MAP_STACK           = 0x00000400
    MAP_NOSYNC          = 0x00000800
    MAP_ANONYMOUS       = 0x00001000
    MAP_GUARD           = 0x00002000
    MAP_EXCL            = 0x00004000
    MAP_NOCORE          = 0x00020000

    # define this alias for compatibility with other os flags
    MAP_FIXED_NOREPLACE = MAP_EXCL

# see: https://github.com/torvalds/linux/blob/master/arch/mips/include/uapi/asm/mman.h
class mips_mmap_flags(Flag):
    MAP_FILE            = 0x00000000
    MAP_SHARED          = 0x00000001
    MAP_PRIVATE         = 0x00000002

    MAP_FIXED           = 0x00000010
    MAP_NORESERVE       = 0x00000400
    MAP_ANONYMOUS       = 0x00000800
    MAP_GROWSDOWN       = 0x00001000
    MAP_DENYWRITE       = 0x00002000
    MAP_EXECUTABLE      = 0x00004000
    MAP_LOCKED          = 0x00008000
    MAP_POPULATE        = 0x00010000
    MAP_NONBLOCK        = 0x00020000
    MAP_STACK           = 0x00040000
    MAP_HUGETLB         = 0x00080000
    MAP_FIXED_NOREPLACE = 0x00100000


# see: https://github.com/apple/darwin-xnu/blob/main/bsd/sys/mman.h
class macos_mmap_flags(Flag):
    MAP_FILE         = 0x00000000
    MAP_SHARED       = 0x00000001
    MAP_PRIVATE      = 0x00000002

    MAP_FIXED        = 0x00000010
    MAP_RENAME       = 0x00000020
    MAP_NORESERVE    = 0x00000040
    MAP_NOEXTEND     = 0x00000100
    MAP_HASSEMAPHORE = 0x00000200
    MAP_NOCACHE      = 0x00000400
    MAP_JIT          = 0x00000800
    MAP_ANONYMOUS    = 0x00001000


# see: https://github.com/vocho/openqnx/blob/master/trunk/lib/c/public/sys/mman.h
class qnx_mmap_flags(Flag):
    MAP_FILE       = 0x00000000
    MAP_SHARED     = 0x00000001
    MAP_PRIVATE    = 0x00000002

    MAP_FIXED      = 0x00000010
    MAP_ELF        = 0x00000020
    MAP_NOSYNCFILE = 0x00000040
    MAP_LAZY       = 0x00000080
    MAP_STACK      = 0x00001000
    MAP_BELOW      = 0x00002000
    MAP_NOINIT     = 0x00004000
    MAP_PHYS       = 0x00010000
    MAP_NOX64K     = 0x00020000
    MAP_BELOW16M   = 0x00040000
    MAP_ANONYMOUS  = 0x00080000
    MAP_SYSRAM     = 0x01000000

    # define this alias for compatibility with other os flags
    MAP_UNINITIALIZED = MAP_NOINIT


class qnx_mmap_prot_flags(QlPrettyFlag):
    PROT_NONE  = 0x00000000
    PROT_READ  = 0x00000001
    PROT_WRITE = 0x00000002
    PROT_EXEC  = 0x00000004

    # not supported by unicorn
    PROT_GROWSDOWN = 0x01000000
    PROT_GROWSUP   = 0x02000000


# fcntl flags
F_DUPFD  = 0
F_GETFD  = 1
F_SETFD  = 2
F_GETFL  = 3
F_SETFL  = 4
F_GETLK  = 5
F_SETLK  = 6
F_SETLKW = 7

FD_CLOEXEC = 1

AT_FDCWD = -100
AT_EMPTY_PATH = 0x1000

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
IPC_PRIVATE = 0

# see: https://elixir.bootlin.com/linux/v5.19.17/source/include/uapi/linux/ipc.h
IPC_CREAT  = 0o0001000  # create if key is nonexistent
IPC_EXCL   = 0o0002000  # fail if key exists
IPC_NOWAIT = 0o0004000  # return error on wait

# see: https://elixir.bootlin.com/linux/v5.19.17/source/include/uapi/linux/shm.h
SHM_W       = 0o000200
SHM_R       = 0o000400
SHM_HUGETLB = 0o004000  # segment will use huge TLB pages
SHM_RDONLY	= 0o010000  # read-only access
SHM_RND		= 0o020000	# round attach address to SHMLBA boundary
SHM_REMAP	= 0o040000	# take-over region on attach
SHM_EXEC	= 0o100000	# execution access

SHMMNI = 4096   # max num of segs system wide

# see: https://elixir.bootlin.com/linux/v5.19.17/source/include/uapi/asm-generic/hugetlb_encode.h
HUGETLB_FLAG_ENCODE_SHIFT = 26
HUGETLB_FLAG_ENCODE_MASK  = 0x3f

# see: https://elixir.bootlin.com/linux/v5.19.17/source/include/uapi/linux/msg.h
MSG_NOERROR = 0o10000  # no error if message is too big
MSG_EXCEPT = 0o20000  # recv any msg except of specified type
MSG_COPY = 0o40000  # copy (not remove) all queue messages

MSGMNI = 32000 # <= IPCMNI, max # of msg queue identifiers
MSGMAX = 8192 # <= INT_MAX, max size of message (bytes)
MSGMNB = 16384 # <= INT_MAX, default max size of a message queue

# ipc syscall
SEMOP       = 1
SEMGET      = 2
SEMCTL      = 3
SEMTIMEDOP  = 4
MSGSND      = 11
MSGRCV      = 12
MSGGET      = 13
MSGCTL      = 14
SHMAT       = 21
SHMDT       = 22
SHMGET      = 23
SHMCTL      = 24
