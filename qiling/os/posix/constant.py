def linux_socket_type_mapping(n):

    linux_socket_types = {
            'SOCK_STREAM'    : 0x1,
            'SOCK_DGRAM'     : 0x2,
            'SOCK_RAW'       : 0x3,
            'SOCK_RDM'       : 0x4,
            'SOCK_SEQPACKET' : 0x5,
            'SOCK_PACKET'    : 0xa,
            }

    d = { v:k for k, v in linux_socket_types.items() }
    return d.get(n)


def linux_socket_family_mapping(n):

    linux_socket_family = {
            'AF_UNSPEC'    : 0x0,
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

    d = { v:k for k, v in linux_socket_family.items() }
    return d.get(n)


def mipsel_socket_type_mapping(n):

    mipsel_socket_types = {
            'SOCK_DGRAM'     : 0x1,
            'SOCK_STREAM'    : 0x2,
            'SOCK_RAW'       : 0x3,
            'SOCK_RDM'       : 0x4,
            'SOCK_SEQPACKET' : 0x5,
            'SOCK_DCCP'      : 0x6,
            'SOCK_PACKET'    : 0xa,
            'SOCK_CLOEXEC'   : 0x80000,
            'SOCK_NONBLOCK'  : 0x80,
            }

    d = { v:k for k, v in mipsel_socket_types.items() }
    return d.get(n)


def mipsel_socket_family_mapping(n):

    mipsel_socket_family = {
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

    d = { v:k for k, v in mipsel_socket_family.items() }
    return d.get(n)


def socket_type_mapping(t, arch):
    return {
            1: linux_socket_type_mapping,
            2: linux_socket_type_mapping,
            6: mipsel_socket_type_mapping,
            }.get(arch)(t)


def socket_family_mapping(p, arch):
    return {
            1: linux_socket_family_mapping,
            2: linux_socket_family_mapping,
            6: mipsel_socket_family_mapping,
            }.get(arch)(p)
